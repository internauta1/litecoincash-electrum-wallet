import hashlib


class TXID:

    #
    # DOUBLE SHA256
    #
    def hash256(self, data):

        return hashlib.sha256(
            hashlib.sha256(data).digest()
        ).digest()

    #
    # REMOVE WITNESS DATA
    #
    def strip_witness(self, rawtx):

        raw = bytes.fromhex(rawtx)

        #
        # Detect SegWit
        #
        if raw[4:6] != b"\x00\x01":
            return raw

        #
        # VERSION
        #
        version = raw[:4]

        pos = 6

        #
        # INPUT COUNT
        #
        input_count = raw[pos]
        pos += 1

        inputs_start = pos

        #
        # PARSE INPUTS
        #
        for _ in range(input_count):

            #
            # txid
            #
            pos += 32

            #
            # vout
            #
            pos += 4

            #
            # scriptSig size
            #
            script_len = raw[pos]
            pos += 1

            #
            # scriptSig
            #
            pos += script_len

            #
            # sequence
            #
            pos += 4

        inputs_end = pos

        #
        # OUTPUT COUNT
        #
        output_count = raw[pos]
        pos += 1

        outputs_start = pos

        #
        # PARSE OUTPUTS
        #
        for _ in range(output_count):

            #
            # value
            #
            pos += 8

            #
            # pk_script size
            #
            script_len = raw[pos]
            pos += 1

            #
            # pk_script
            #
            pos += script_len

        outputs_end = pos

        #
        # SKIP WITNESS
        #
        for _ in range(input_count):

            item_count = raw[pos]
            pos += 1

            for _ in range(item_count):

                item_len = raw[pos]
                pos += 1

                pos += item_len

        #
        # LOCKTIME
        #
        locktime = raw[pos:pos + 4]

        #
        # REBUILD NON-WITNESS TX
        #
        stripped = (
            version +
            raw[6:inputs_end] +
            raw[inputs_end:outputs_end] +
            locktime
        )

        return stripped

    #
    # TXID
    #
    def calculate(self, rawtx):

        stripped = self.strip_witness(rawtx)

        txid = self.hash256(
            stripped
        )[::-1].hex()

        return txid

    #
    # WTXID
    #
    def calculate_wtxid(self, rawtx):

        raw = bytes.fromhex(rawtx)

        wtxid = self.hash256(
            raw
        )[::-1].hex()

        return wtxid
