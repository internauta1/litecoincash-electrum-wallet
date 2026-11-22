# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import hashlib
import threading
import time
from typing import Optional, Dict, Mapping, Sequence, TYPE_CHECKING
from pathlib import Path

from . import util
from .bitcoin import hash_encode
from .crypto import sha256d
from .lcc_header_rules import classify_header, LAST_SCRYPT_BLOCK, HIVE_ACTIVATION_HEIGHT, FIRST_HIVE_BLOCK_HEIGHT
from . import constants
from .util import bfh, with_lock
from .logging import Logger

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


HEADER_SIZE = 80  # bytes
CHUNK_SIZE = 2016  # num headers in a difficulty retarget period

# see https://github.com/litecoin-project/litecoin/blob/0.21/src/chainparams.cpp#L78
MAX_TARGET = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  # compact: 0x1e0ffff0


class MissingHeader(Exception):
    pass


class InvalidHeader(Exception):
    pass


def serialize_header(header_dict: dict) -> bytes:
    s = (
        int.to_bytes(header_dict['version'], length=4, byteorder="little", signed=False)
        + bfh(header_dict['prev_block_hash'])[::-1]
        + bfh(header_dict['merkle_root'])[::-1]
        + int.to_bytes(int(header_dict['timestamp']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['bits']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['nonce']), length=4, byteorder="little", signed=False))
    return s


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) != HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    h = {}
    h['version'] = int.from_bytes(s[0:4], byteorder='little')
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = int.from_bytes(s[68:72], byteorder='little')
    h['bits'] = int.from_bytes(s[72:76], byteorder='little')
    h['nonce'] = int.from_bytes(s[76:80], byteorder='little')
    h['block_height'] = height
    return h


def hash_header(header: Optional[dict]) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: bytes) -> str:
    assert isinstance(header, bytes)
    return hash_encode(sha256d(header))


def pow_hash_header(header: dict) -> str:
    """Return LCC PoW hash only for supported algorithms."""
    height = header['block_height']

    if height < 1371112:
        raw = serialize_header(header)
        return hashlib.scrypt(
            raw, salt=raw, n=1024, r=1, p=1, dklen=32
        )[::-1].hex()

    pow_type = classify_header(
        height, header['version'], header['nonce']
    )

    if pow_type == 'sha256d':
        return hash_raw_header(serialize_header(header))

    # LCC_MINOTAURX_POW_HASH_V1
    # Core GetPoWHash() uses MinotaurX for this PoW type.
    # Block identity remains SHA256d via hash_header().
    # This function does NOT establish BIP9 activation,
    # difficulty correctness or authorization to connect.
    if pow_type == 'minotaurx':
        if height < 2540160:
            raise NotImplementedError(
                "MinotaurX before mainnet activation boundary"
            )

        from .lcc_minotaurx import minotaurx_hash

        raw = serialize_header(header)

        if len(raw) != 80:
            raise ValueError("Invalid MinotaurX header length")

        result = minotaurx_hash(raw)

        if not isinstance(result, bytes) or len(result) != 32:
            raise ValueError("Invalid native MinotaurX result")

        return result[::-1].hex()

    raise NotImplementedError(
        f"LCC {pow_type} proof verification is not implemented"
    )

# block hash -> chain work; up to and including that block

# Exact, branch-specific pre-Hive chainwork checkpoints.
# Deliberately separate from Electrum's legacy retarget cache.
_LCC_PRE_HIVE_CHAINWORK_CACHE = {}

_CHAINWORK_CACHE = {
    "0000000000000000000000000000000000000000000000000000000000000000": 0,  # virtual block at height -1
}  # type: Dict[str, int]


class BlockchainManager(Logger):

    def __init__(self, *, headers_dir: Path):
        Logger.__init__(self)
        self.headers_dir = headers_dir
        self.forks_dir = headers_dir / 'forks'
        util.make_dir(self.forks_dir)

        # key: blockhash hex at forkpoint
        # the chain at some key is the best chain that includes the given hash
        self.blockchains = {}  # type: Dict[str, Blockchain]
        self.blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock

        self._read_blockchains()
        self._init_headers_file_for_best_chain()
        self.logger.info(f"blockchains {list(map(lambda b: b.forkpoint, self.blockchains.values()))}")

    @classmethod
    def from_config(cls, config: 'SimpleConfig') -> 'BlockchainManager':
        headers_dir = util.get_headers_dir(config)
        return cls(headers_dir=Path(headers_dir))

    def _read_blockchains(self):
        best_chain = Blockchain(
            bc_mgr=self,
            forkpoint=0,
            parent=None,
            forkpoint_hash=constants.net.GENESIS,
            prev_hash=None,
        )
        self.blockchains[constants.net.GENESIS] = best_chain

        # consistency checks
        if best_chain.height() > constants.net.max_checkpoint():
            header_after_cp = best_chain.read_header(constants.net.max_checkpoint()+1)
            if not header_after_cp or not best_chain.can_connect(header_after_cp, check_height=False):
                self.logger.warning("[blockchain] deleting best chain. cannot connect header after last cp to last cp.")
                best_chain.path().unlink()
                best_chain.update_size()

        # forks
        # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
        l = filter(lambda x: x.startswith('fork2_') and '.' not in x, os.listdir(self.forks_dir))
        l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

        for filename in l:
            self._instantiate_chain(filename)

    def _instantiate_chain(self, filename: str):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            self._delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in self.blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            self._delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(
            bc_mgr=self,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=first_hash,
            prev_hash=prev_hash,
        )
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h):
            self._delete_chain(filename, "incorrect first hash for chain")
            return
        if not b.parent.can_connect(h, check_height=False):
            self._delete_chain(filename, "cannot connect chain to parent")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        self.blockchains[chain_id] = b

    def _delete_chain(self, filename: str, reason: str):
        self.logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        file = self.forks_dir / filename
        file.unlink()

    def _init_headers_file_for_best_chain(self):
        b = self.get_best_chain()
        filename = b.path()
        length = HEADER_SIZE * len(constants.net.CHECKPOINTS) * CHUNK_SIZE
        if not filename.exists() or filename.stat().st_size < length:
            with open(filename, 'wb') as f:
                if length > 0:
                    f.seek(length - 1)
                    f.write(b'\x00')
            util.ensure_sparse_file(filename)
        with b.lock:
            b.update_size()

    def get_best_chain(self) -> 'Blockchain':
        return self.blockchains[constants.net.GENESIS]

    def check_header(self, header: dict) -> Optional['Blockchain']:
        """Returns any Blockchain that contains header, or None."""
        if type(header) is not dict:
            return None
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.check_header(header):
                return b
        return None

    def can_connect(self, header: dict) -> Optional['Blockchain']:
        """Returns the Blockchain that has a tip that directly links up
        with header, or None.
        """
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.can_connect(header):
                return b
        return None

    def get_chains_that_contain_header(self, height: int, header_hash: str) -> Sequence['Blockchain']:
        """Returns a list of Blockchains that contain header, best chain first."""
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        chains = [chain for chain in chains
                  if chain.check_hash(height=height, header_hash=header_hash)]
        chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
        return chains


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(
        self,
        *,
        bc_mgr: 'BlockchainManager',
        forkpoint: int,
        parent: Optional['Blockchain'],
        forkpoint_hash: str,
        prev_hash: Optional[str],
    ):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.bc_mgr = bc_mgr
        if parent is not None:
            assert bc_mgr is parent.bc_mgr
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.update_size()

    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with self.bc_mgr.blockchains_lock:
            return list(filter(lambda y: y.parent==self, self.bc_mgr.blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with self.lock, self.bc_mgr.blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(
            bc_mgr=parent.bc_mgr,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=hash_header(header),
            prev_hash=parent.get_hash(forkpoint-1),
        )
        self.assert_headers_file_available(parent.path())
        open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with parent.bc_mgr.blockchains_lock:
            parent.bc_mgr.blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        p = self.path()
        self._size = os.path.getsize(p)//HEADER_SIZE if p.exists() else 0

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise InvalidHeader("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise InvalidHeader("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        bits = cls.target_to_bits(target)
        if bits != header.get('bits'):
            raise InvalidHeader("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        _pow_hash = pow_hash_header(header)
        pow_hash_as_num = int.from_bytes(bfh(_pow_hash), byteorder='big')
        if pow_hash_as_num > target:
            raise InvalidHeader(f"insufficient proof of work: {pow_hash_as_num} vs target {target}")

    def verify_chunk(self, index: int, data: bytes) -> None:
        """Verify LCC headers using their consensus-era difficulty."""
        if not data or len(data) % HEADER_SIZE:
            raise InvalidHeader("invalid header chunk length")

        num = len(data) // HEADER_SIZE
        start_height = index * CHUNK_SIZE
        prev_hash = self.get_hash(start_height - 1)

        scrypt_target = None
        history = {}

        # DGW needs the previous 24 SHA256d headers.
        # When the chunk begins after the fork, load them
        # from the already verified local header store.
        if (
            not constants.net.TESTNET
            and start_height >= LAST_SCRYPT_BLOCK + 25
        ):
            for h in range(start_height - 24, start_height):
                previous = self.read_header(h)
                if previous is None:
                    raise MissingHeader()
                history[h] = previous

        for i in range(num):
            height = start_height + i
            raw_header = data[
                i * HEADER_SIZE:(i + 1) * HEADER_SIZE
            ]
            header = deserialize_header(raw_header, height)

            if constants.net.TESTNET:
                target = self.get_target(index - 1)

            elif height <= LAST_SCRYPT_BLOCK:
                if scrypt_target is None:
                    scrypt_target = self.get_target(index - 1)
                target = scrypt_target

            elif height < FIRST_HIVE_BLOCK_HEIGHT:
                if height >= HIVE_ACTIVATION_HEIGHT and classify_header(
                        height, header["version"], header["nonce"]) != "sha256d":
                    raise InvalidHeader("Hive proof not supported")
                try:
                    bits = self.dgw_next_bits_early(
                        height, history
                    )
                except KeyError as e:
                    raise MissingHeader() from e

                target = self.bits_to_target(bits)

            else:
                raise NotImplementedError(
                    "LCC header verification after Hive "
                    "activation is not implemented"
                )

            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None

            self.verify_header(
                header,
                prev_hash,
                target,
                expected_header_hash,
            )

            prev_hash = hash_header(header)
            history[height] = header

    @with_lock
    def path(self) -> Path:
        if self.parent is None:
            return self.bc_mgr.headers_dir / 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            return self.bc_mgr.forks_dir / basename

    @with_lock
    def save_chunk(self, index: int, chunk: bytes):
        assert index >= 0, index
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = self.bc_mgr.get_best_chain()
            main_chain.save_chunk(index, chunk)
            return

        delta_height = (index * CHUNK_SIZE - self.forkpoint)
        delta_bytes = delta_height * HEADER_SIZE
        # if this chunk contains our forkpoint, only save the part after forkpoint
        # (the part before is the responsibility of the parent)
        if delta_bytes < 0:
            chunk = chunk[-delta_bytes:]
            delta_bytes = 0
        truncate = not chunk_within_checkpoint_region
        self.write(chunk, delta_bytes, truncate)
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        with self.lock, self.bc_mgr.blockchains_lock:
            # do the swap; possibly multiple ones
            cnt = 0
            while True:
                old_parent = self.parent
                if not self._swap_with_parent():
                    break
                # make sure we are making progress
                cnt += 1
                if cnt > len(self.bc_mgr.blockchains):
                    raise Exception(f'swapping fork with parent too many times: {cnt}')
                # we might have become the parent of some of our former siblings
                for old_sibling in old_parent.get_direct_children():
                    if self.check_hash(old_sibling.forkpoint - 1, old_sibling._prev_hash):
                        old_sibling.parent = self

    def _swap_with_parent(self) -> bool:
        """Check if this chain became stronger than its parent, and swap
        the underlying files if so. The Blockchain instances will keep
        'containing' the same headers, but their ids change and so
        they will be stored in different files."""
        if self.parent is None:
            return False
        if self.parent.get_chainwork() >= self.get_chainwork():
            return False
        self.logger.info(f"swapping {self.forkpoint} {self.parent.forkpoint}")
        parent_branch_size = self.parent.height() - self.forkpoint + 1
        forkpoint = self.forkpoint  # type: Optional[int]
        parent = self.parent  # type: Optional[Blockchain]
        child_old_id = self.get_id()
        parent_old_id = parent.get_id()
        # swap files
        # child takes parent's name
        # parent's new name will be something new (not child's old name)
        self.assert_headers_file_available(self.path())
        child_old_name = self.path()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        assert forkpoint > parent.forkpoint, (f"forkpoint of parent chain ({parent.forkpoint}) "
                                              f"should be at lower height than children's ({forkpoint})")
        with open(parent.path(), 'rb') as f:
            f.seek((forkpoint - parent.forkpoint)*HEADER_SIZE)
            parent_data = f.read(parent_branch_size*HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (forkpoint - parent.forkpoint)*HEADER_SIZE)
        # swap parameters
        self.parent, parent.parent = parent.parent, self  # type: Optional[Blockchain], Optional[Blockchain]
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self._forkpoint_hash, parent._forkpoint_hash = parent._forkpoint_hash, hash_raw_header(parent_data[:HEADER_SIZE])
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        # parent's new name
        os.replace(child_old_name, parent.path())
        self.update_size()
        parent.update_size()
        # update pointers
        blockchains = self.bc_mgr.blockchains
        blockchains.pop(child_old_id, None)
        blockchains.pop(parent_old_id, None)
        blockchains[self.get_id()] = self
        blockchains[parent.get_id()] = parent
        return True

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path: Path):
        if path.exists():
            return
        elif not self.bc_mgr.headers_dir.exists():
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    @with_lock
    def write(self, data: bytes, offset: int, truncate: bool = True, *, fsync: bool = True) -> None:
        filename = self.path()
        self.assert_headers_file_available(filename)
        with open(filename, 'rb+') as f:
            if truncate and offset != self._size * HEADER_SIZE:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            if fsync:
                f.flush()
                os.fsync(f.fileno())
        self.update_size()

    @with_lock
    def save_header(self, header: dict) -> None:
        delta = header.get('block_height') - self.forkpoint
        data = serialize_header(header)
        # headers are only _appended_ to the end:
        assert delta == self.size(), (delta, self.size())
        assert len(data) == HEADER_SIZE
        # note: we don't fsync, to improve perf. losing headers at end of file is ok.
        self.write(data, delta*HEADER_SIZE, fsync=False)
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int) -> Optional[dict]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(delta * HEADER_SIZE)
            h = f.read(HEADER_SIZE)
            if len(h) < HEADER_SIZE:
                raise Exception('Expected to read a full header. This was only {} bytes'.format(len(h)))
        if h == bytes([0])*HEADER_SIZE:
            return None
        return deserialize_header(h, height)

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)

    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= constants.net.max_checkpoint()
            at_chunk_boundary = (height+1) % CHUNK_SIZE == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif is_height_checkpoint():
            index = height // CHUNK_SIZE
            h, t, _ = self.checkpoints[index]
            return h
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_timestamp(self, height):
        if height < len(self.checkpoints) * CHUNK_SIZE and (height+1) % CHUNK_SIZE == 0:
            index = height // CHUNK_SIZE
            _, _, ts = self.checkpoints[index]
            return ts
        return self.read_header(height).get('timestamp')

    @classmethod
    def dgw_next_bits_early(cls, height: int, headers: dict) -> int:
        """LCC Dark Gravity Wave for early post-fork SHA256d blocks.

        This version applies before Hive activation. It does not
        implement skipping Hive blocks or later consensus rules.
        """
        last_scrypt = 1371111
        window = 24
        spacing = 150
        pow_limit = int("00000000" + "ff" * 28, 16)

        if height <= last_scrypt:
            raise ValueError("DGW not active at this height")

        if height - 1 - last_scrypt < window:
            return cls.target_to_bits(pow_limit)

        average = 0

        for n in range(1, window + 1):
            previous = headers[height - n]
            target = cls.bits_to_target(previous["bits"])

            if n == 1:
                average = target
            else:
                average = (average * n + target) // (n + 1)

        first = headers[height - window]
        last = headers[height - 1]

        actual = last["timestamp"] - first["timestamp"]
        expected = window * spacing

        actual = max(expected // 3, actual)
        actual = min(expected * 3, actual)

        target = min(
            average * actual // expected,
            pow_limit,
        )

        return cls.target_to_bits(target)


    @classmethod
    def dgw_next_bits_pre_hive11(cls, height: int, headers: dict) -> int:
        """LCC SHA256d DGW with Hive blocks, before Hive 1.1.

        Historical consensus rule:
        - Skip Hive blocks in the 24-block PoW average.
        - Keep the immediate previous block for the tip timestamp,
          even if that previous block is Hive.

        Does not validate Hive proofs or support Hive 1.1.
        """
        from .lcc_header_rules import (
            LAST_SCRYPT_BLOCK,
            classify_header,
        )

        window = 24
        spacing = 150
        pow_limit = int("00000000" + "ff" * 28, 16)

        if height <= LAST_SCRYPT_BLOCK:
            raise ValueError("DGW not active at this height")

        if height - 1 - LAST_SCRYPT_BLOCK < window:
            return cls.target_to_bits(pow_limit)

        tip = height - 1
        cursor = tip
        average = 0

        def is_hive(block_height):
            header = headers[block_height]
            return classify_header(
                block_height,
                header["version"],
                header["nonce"],
            ) == "hive"

        for n in range(1, window + 1):
            while is_hive(cursor):
                cursor -= 1

            target = cls.bits_to_target(
                headers[cursor]["bits"]
            )

            if n == 1:
                average = target
            else:
                average = (
                    average * n + target
                ) // (n + 1)

            if n != window:
                cursor -= 1

        actual = (
            headers[tip]["timestamp"]
            - headers[cursor]["timestamp"]
        )

        expected = window * spacing
        actual = max(expected // 3, actual)
        actual = min(expected * 3, actual)

        target = min(
            average * actual // expected,
            pow_limit,
        )

        return cls.target_to_bits(target)

    def get_target(self, index: int) -> int:
        # compute target from chunk x, used in chunk x+1
        if constants.net.TESTNET:
            return 0
        if index == -1:
            return 0x00000FFFF0000000000000000000000000000000000000000000000000000000
        if index < len(self.checkpoints):
            h, t, _ = self.checkpoints[index]
            return t
        # new target
        # Litecoin: go back the full period unless it's the first retarget
        first_timestamp = self.get_timestamp(index * CHUNK_SIZE - 1 if index > 0 else 0)
        last = self.read_header((index+1) * CHUNK_SIZE - 1)
        if not first_timestamp or not last:
            raise MissingHeader()
        bits = last.get('bits')
        target = self.bits_to_target(bits)
        nActualTimespan = last.get('timestamp') - first_timestamp
        nTargetTimespan = 84 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target * nActualTimespan) // nTargetTimespan)
        # not any target can be represented in 32 bits:
        new_target = self.bits_to_target(self.target_to_bits(new_target))
        return new_target

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        # arith_uint256::SetCompact in Bitcoin Core
        if not (0 <= bits < (1 << 32)):
            raise InvalidHeader(f"bits should be uint32. got {bits!r}")
        bitsN = (bits >> 24) & 0xff
        bitsBase = bits & 0x7fffff
        if bitsN <= 3:
            target = bitsBase >> (8 * (3-bitsN))
        else:
            target = bitsBase << (8 * (bitsN-3))
        if target != 0 and bits & 0x800000 != 0:
            # Bit number 24 (0x800000) represents the sign of N
            raise InvalidHeader("target cannot be negative")
        if (target != 0 and
                (bitsN > 34 or
                 (bitsN > 33 and bitsBase > 0xff) or
                 (bitsN > 32 and bitsBase > 0xffff))):
            raise InvalidHeader("target has overflown")
        return target

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        # arith_uint256::GetCompact in Bitcoin Core
        # see https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
        c = target.to_bytes(length=32, byteorder='big')
        bitsN = len(c)
        while bitsN > 0 and c[0] == 0:
            c = c[1:]
            bitsN -= 1
            if len(c) < 3:
                c += b'\x00'
        bitsBase = int.from_bytes(c[:3], byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header_at_height(self, height: int) -> int:
        """work done by single header at given height"""
        chunk_idx = height // CHUNK_SIZE - 1
        target = self.get_target(chunk_idx)
        work = ((2 ** 256 - target - 1) // (target + 1)) + 1
        return work

    @with_lock
    # LCC_EXACT_PRE_HIVE_CHAINWORK_V1
    def get_chainwork(self, height=None) -> int:
        """Accumulate individual header work on the selected branch.

        Mainnet Hive chainwork is deliberately unavailable until
        its Core-specific consensus multipliers are integrated.
        """
        if height is None:
            height = max(0, self.height())

        if type(height) is not int or height < 0:
            raise ValueError("Invalid chainwork height")

        if constants.net.TESTNET:
            return height

        # LCC_HIVE_CHAINWORK_INTEGRATION_V1
        from .lcc_chainwork import base_work

        if height >= FIRST_HIVE_BLOCK_HEIGHT:
            from functools import lru_cache
            from .lcc_chainwork import (
                block_work,
                core_difficulty_from_bits,
            )
            from .lcc_bip9 import (
                cached_state_for_height,
                State,
            )
            from .lcc_mainnet import mainnet_bip9_deployments

            deployment = mainnet_bip9_deployments()["hive11"]

            @lru_cache(maxsize=2048)
            def work_header(h):
                if type(h) is not int or h < 0 or h > height:
                    return None

                item = self.read_header(h)

                if item is None:
                    raise MissingHeader()

                if item.get("block_height") != h:
                    raise InvalidHeader(
                        "Chainwork historical height mismatch"
                    )

                return item

            def is_hive(h):
                item = work_header(h)

                return (
                    item is not None
                    and h >= HIVE_ACTIVATION_HEIGHT
                    and item.get("nonce") == 192
                )

            def hive11_enabled(h):
                # Core GetBlockProof calls IsHive11Enabled
                # with the current block index. This tests
                # the state applicable to the next block.
                return (
                    cached_state_for_height(
                        h + 1,
                        work_header,
                        deployment,
                    ) == State.ACTIVE
                )

            def hive_difficulty(h):
                item = work_header(h)

                if item is None:
                    raise MissingHeader()

                return core_difficulty_from_bits(
                    int(item["bits"])
                )

        # Independent cache: do not use the previous approximation.
        cache = _LCC_PRE_HIVE_CHAINWORK_CACHE

        total = 0
        start = 0

        # Find the closest cached ancestor on this exact branch.
        checkpoint = height // CHUNK_SIZE * CHUNK_SIZE

        while checkpoint > 0:
            checkpoint_hash = self.get_hash(checkpoint)
            cached = cache.get(checkpoint_hash)

            if cached is not None:
                total = cached
                start = checkpoint + 1
                break

            checkpoint -= CHUNK_SIZE

        for h in range(start, height + 1):
            header = self.read_header(h)

            if header is None:
                raise MissingHeader()

            if h >= FIRST_HIVE_BLOCK_HEIGHT:
                total += block_work(
                    height=h,
                    get_header=work_header,
                    is_hive=is_hive,
                    hive11_enabled=hive11_enabled,
                    hive_difficulty=hive_difficulty,
                )
            else:
                total += base_work(int(header["bits"]))

            # Cache only complete intervals, keyed by block hash.
            if h > 0 and h % CHUNK_SIZE == 0:
                cache[self.get_hash(h)] = total

        return total


    def can_connect(self, header: Optional[dict], *, check_height: bool = True) -> bool:
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            if constants.net.TESTNET:
                # Preserve existing testnet behavior.
                target = self.get_target(
                    height // CHUNK_SIZE - 1
                )

            elif height <= LAST_SCRYPT_BLOCK:
                # Original Litecoin difficulty rules.
                target = self.get_target(
                    height // CHUNK_SIZE - 1
                )

            elif height < FIRST_HIVE_BLOCK_HEIGHT:
                # LCC SHA256d before the first actual Hive block.
                if height >= HIVE_ACTIVATION_HEIGHT and classify_header(
                        height, header["version"], header["nonce"]) != "sha256d":
                    return False
                history = {}

                needs_history = (
                    height - 1 - LAST_SCRYPT_BLOCK >= 24
                )

                if needs_history:
                    for h in range(height - 24, height):
                        previous = self.read_header(h)
                        if previous is None:
                            return False
                        history[h] = previous

                bits = self.dgw_next_bits_early(
                    height, history
                )

                target = self.bits_to_target(bits)

            else:
                # LCC_EXPERIMENTAL_FIRST_HIVE_SPV_V2
                # Experimental, explicitly enabled and
                # restricted to an isolated test directory.
                import os

                if (
                    os.environ.get(
                        "ELECTRUM_LCC_EXPERIMENTAL_HIVE_SPV"
                    ) != "1"
                    or "beta2-hive-experimental-"
                    not in str(self.path())
                ):
                    return False

                # LCC_EXPERIMENTAL_SUBSEQUENT_HIVE_V1
                if classify_header(
                    height, header['version'], header['nonce']
                ) == 'hive':
                    # LCC_EXPERIMENTAL_HIVE_EPOCH_GATES_V1
                    if (
                        height > FIRST_HIVE_BLOCK_HEIGHT + 2048
                        and os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_HIVE11_CONTINUATION"
                        ) != "1"
                    ):
                        return False

                    if (
                        height >= 2540160
                        and os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_MINOTAURX_CONTINUATION"
                        ) != "1"
                    ):
                        return False

                    receipt = getattr(
                        self,
                        "_lcc_experimental_hive_receipt",
                        None,
                    )
                    return receipt == (
                        height,
                        prev_hash,
                        hash_header(header),
                    )

                # LCC_EXPERIMENTAL_MINOTAURX_LWMA_V1
                # Only on an isolated chain with all three opt-ins.
                # Hive candidates still require a verified receipt.
                if height >= 2540160:
                    if (
                        os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_HIVE11_CONTINUATION"
                        ) != "1"
                        or os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_MINOTAURX_CONTINUATION"
                        ) != "1"
                    ):
                        return False

                    from .lcc_postfork_pow import (
                        verify_postfork_pow_header,
                    )

                    result = verify_postfork_pow_header(
                        candidate_header=header,
                        get_header=self.read_header,
                    )

                    return result.get("pow_verified") is True

                # LCC_EXPERIMENTAL_DGW_HIVE11_CONTINUATION_V1
                # A separate opt-in is mandatory beyond the
                # original 2048-block laboratory window.
                if height > FIRST_HIVE_BLOCK_HEIGHT + 2048:
                    if (
                        os.environ.get(
                            "ELECTRUM_LCC_EXPERIMENTAL_HIVE11_CONTINUATION"
                        ) != "1"
                        or height >= 2540160
                    ):
                        return False

                    if classify_header(
                        height,
                        header["version"],
                        header["nonce"],
                    ) != "sha256d":
                        return False

                    from .lcc_bip9 import (
                        State,
                        cached_state_for_height,
                    )
                    from .lcc_mainnet import mainnet_bip9_deployments
                    from .lcc_dgw_hive11 import next_dgw_bits

                    # Core checks Hive 1.1 using pindexLast,
                    # the parent of the candidate block.
                    deployment = mainnet_bip9_deployments()["hive11"]

                    hive11_active = (
                        cached_state_for_height(
                            height,
                            self.read_header,
                            deployment,
                        ) == State.ACTIVE
                    )

                    expected_bits = next_dgw_bits(
                        height=height,
                        get_header=self.read_header,
                        hive11_active=hive11_active,
                    )

                    self.verify_header(
                        header,
                        prev_hash,
                        self.bits_to_target(expected_bits),
                    )
                    return True

                # LCC_EXPERIMENTAL_POST_HIVE_SHA256D_V1
                # Restricted laboratory continuation.
                # Do not cross into Hive 1.1 or MinotaurX.
                if not (
                    FIRST_HIVE_BLOCK_HEIGHT < height
                    <= FIRST_HIVE_BLOCK_HEIGHT + 2048
                ):
                    return False

                if classify_header(
                    height,
                    header["version"],
                    header["nonce"],
                ) != "sha256d":
                    return False

                from .lcc_bip9 import (
                    cached_state_for_height,
                    State,
                )
                from .lcc_mainnet import (
                    mainnet_bip9_deployments,
                )

                deployment = mainnet_bip9_deployments()["hive11"]

                if cached_state_for_height(
                    height,
                    self.read_header,
                    deployment,
                ) == State.ACTIVE:
                    return False

                history = {}
                cursor = height - 1
                pow_count = 0

                # Include intervening Hive headers, but only
                # count SHA256d blocks in the DGW window.
                while (
                    pow_count < 24
                    and cursor >= 0
                    and height - cursor <= 256
                ):
                    previous = self.read_header(cursor)

                    if previous is None:
                        return False

                    kind = classify_header(
                        cursor,
                        previous["version"],
                        previous["nonce"],
                    )

                    if kind not in ("sha256d", "hive"):
                        return False

                    history[cursor] = previous

                    if kind == "sha256d":
                        pow_count += 1

                    cursor -= 1

                if pow_count != 24:
                    return False

                expected_bits = self.dgw_next_bits_pre_hive11(
                    height,
                    history,
                )

                self.verify_header(
                    header,
                    prev_hash,
                    self.bits_to_target(expected_bits),
                )

                return True

            self.verify_header(
                header,
                prev_hash,
                target,
            )

        except Exception:
            return False

        return True


    @staticmethod
    def _lcc_core_hash(height):
        import subprocess

        result = subprocess.run(
            ["docker", "exec", "lcc-node",
             "/opt/litecoincash/bin/litecoincash-cli",
             "getblockhash", str(height)],
            capture_output=True, text=True,
            check=True, timeout=30,
        )
        value = result.stdout.strip().lower()
        if len(value) != 64 or any(
            c not in "0123456789abcdef" for c in value
        ):
            raise InvalidHeader("Core returned invalid hash")
        return value

    def _lcc_verify_core_chunk(self, idx, data):
        import hashlib

        if not data or len(data) % HEADER_SIZE:
            raise InvalidHeader("Invalid chunk length")

        start = idx * CHUNK_SIZE
        end = start + len(data) // HEADER_SIZE - 1
        old_tip = self.height()

        if end < FIRST_HIVE_BLOCK_HEIGHT:
            raise InvalidHeader("Core mode before Hive forbidden")
        if start > old_tip + 1:
            raise MissingHeader()

        previous = self.get_hash(start - 1)
        if previous != self._lcc_core_hash(start - 1):
            raise InvalidHeader("Core start anchor mismatch")

        previous_wire = bytes.fromhex(previous)[::-1]

        for offset in range(0, len(data), HEADER_SIZE):
            height = start + offset // HEADER_SIZE
            raw = data[offset:offset + HEADER_SIZE]

            if raw[4:36] != previous_wire:
                raise InvalidHeader(
                    f"Broken header link at {height}"
                )

            previous_wire = hashlib.sha256(
                hashlib.sha256(raw).digest()
            ).digest()

            if height <= old_tip:
                actual = previous_wire[::-1].hex()
                if self.get_hash(height) != actual:
                    raise InvalidHeader(
                        f"Existing header mismatch at {height}"
                    )

        if previous_wire[::-1].hex() != self._lcc_core_hash(end):
            raise InvalidHeader(
                f"Core end anchor mismatch at {end}"
            )

        self.logger.info(
            f"LCC CORE-ASSISTED NOT SPV: "
            f"verified chunk {idx}, heights {start}-{end}"
        )

    def connect_chunk(self, idx: int, data: bytes) -> bool:
        assert idx >= 0, idx
        try:
            # All headers must pass independent local consensus checks.
            # Unsupported Hive rules fail closed; no trusted-Core bypass.
            self.verify_chunk(idx, data)

            self.save_chunk(idx, data)
            return True

        except Exception as e:
            self.logger.error(
                f"LCC chunk {idx} rejected: {e!r}"
            )
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // CHUNK_SIZE
        for index in range(n):
            h = self.get_hash((index+1) * CHUNK_SIZE -1)
            target = self.get_target(index)
            # Litecoin: also store the timestamp of the last block
            tstamp = self.get_timestamp((index+1) * CHUNK_SIZE - 1)
            cp.append((h, target, tstamp))
        return cp
