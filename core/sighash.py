import hashlib
import struct


class Sighash:

    #
    # DOUBLE SHA256
    #
    def dsha(self, b):

        return hashlib.sha256(
            hashlib.sha256(b).digest()
        ).digest()

    #
    # VARINT
    #
    def varint(self, n):

        if n < 0xfd:
            return bytes([n])

        elif n <= 0xffff:
            return b"\xfd" + struct.pack("<H", n)

        elif n <= 0xffffffff:
            return b"\xfe" + struct.pack("<I", n)

        else:
            return b"\xff" + struct.pack("<Q", n)

    #
    # CREATE REAL BITCOIN/LCC SIGHASH
    #
    def create_sighash(
        self,
        tx,
        input_index,
        script_pubkey,
        value
    ):

        version = struct.pack(
            "<I",
            tx["version"]
        )

        #
        # INPUTS
        #
        inputs = b""

        for i, inp in enumerate(tx["inputs"]):

            txid = bytes.fromhex(
                inp["txid"]
            )[::-1]

            vout = struct.pack(
                "<I",
                inp["vout"]
            )

            #
            # ONLY CURRENT INPUT GETS SCRIPT
            #
            if i == input_index:

                script = (
                    self.varint(
                        len(script_pubkey)
                    ) +
                    script_pubkey
                )

            else:
                script = b"\x00"

            sequence = b"\xff\xff\xff\xff"

            inputs += (
                txid +
                vout +
                script +
                sequence
            )

        inputs = (
            self.varint(
                len(tx["inputs"])
            ) +
            inputs
        )

        #
        # OUTPUTS
        #
        outputs = b""

        for out in tx["outputs"]:

            value_bytes = struct.pack(
                "<Q",
                out["value"]
            )

            h160 = bytes.fromhex(
                tx["change_h160"]
            )

            script = (
                b"\x76\xa9\x14" +
                h160 +
                b"\x88\xac"
            )

            outputs += (
                value_bytes +
                self.varint(len(script)) +
                script
            )

        outputs = (
            self.varint(
                len(tx["outputs"])
            ) +
            outputs
        )

        locktime = struct.pack(
            "<I",
            tx["locktime"]
        )

        #
        # BCH/LCC FORKID
        #
        sighash_type = struct.pack(
            "<I",
            0x41
        )

        preimage = (
            version +
            inputs +
            outputs +
            locktime +
            sighash_type
        )

        return self.dsha(preimage)
