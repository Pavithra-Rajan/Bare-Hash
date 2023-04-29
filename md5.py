import logging
import math
import argparse

logging.basicConfig(format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()

logger.setLevel(logging.DEBUG)


def gen_K(i):
    return int(abs(math.sin(i + 1)) * (2**32))


K = [gen_K(i) for i in range(64)]

shifts = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21]
]

# the start values for the initialisation vector (all values in little-endian)
A_start = 0x67452301
B_start = 0xefcdab89
C_start = 0x98badcfe
D_start = 0x10325476


class MD5:
    def padding(self, message):
        """
        This function does the padding of the message so that it is a multiple of 512 bits.
        Step 1:
            Add a single "1" bit to the end of the message
        Step 2:
            Add a fixed number of "0"s to the end of the message. Let the number of 0s be k
            If l is the size of the message, then l + k + 1 mod 512 should be 64
        Step 3:
            Append 64 bit binary representation of l which is the length of the message
        """
        length = len(message) * 8  # len gives number of bytes so multiply by 8 to get bits
        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0:
            message.append(0x00)

        message += length.to_bytes(8, 'little')  # Convert to bytes with little-endian format.
        if (len(message) * 8) % 512 != 0:
            logger.error("Padding not completed and message not a multiple of 512 bits")
            exit(1)

        return message

    def parsing(self, padded_message):
        """
        Return blocks of 512 bits of the padded message as a list
        Args:
            padded_message: The message padded to be a multiple of 512 bits
        """
        blocks = []  # contains 512-bit blocks of message
        for i in range(0, len(padded_message), 64):  # 64 bytes is 512 bits
            blocks.append(padded_message[i:i + 64])
        return blocks

    def generate_hash(self, message) -> bytes:
        """
        This function takes in the message and returns the SHA256 hash of it.
        Args:
            message: The message to be hashed via SHA256
        """

        # Type checking and type casting accordingly
        if isinstance(message, str):
            message = bytearray(message, 'ascii')   # encode to bytearray object with ASCII format
        elif isinstance(message, bytes):
            message = bytearray(message)
        elif not isinstance(message, bytearray):
            raise TypeError

        # pad the message to fit into 512 bit blocks
        padded_message = self.padding(message)

        # split the message into separate blocks
        blocks = self.parsing(padded_message)

        # initialise the initialisation vectors
        A = A_start
        B = B_start
        C = C_start
        D = D_start

        for block in blocks:

            # save the values of initialisation vector before starting the block
            _A, _B, _C, _D = A, B, C, D

            # the following array stores the values for each of the 4 rounds of md5.
            # the values are as follows
            # [
            #   the function that will be used,
            #   the order in which the 16 words in the block will be processed
            #   the k values used (obtained from sin) for each of the 16 words,
            #   the amount to shift each of the 16 words in the block
            # ]
            roundwise_values = [
                [   # round 1
                    lambda B, C, D: (B & C) | (~B & D),
                    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                    K[:16],
                    [shifts[0][i % 4] for i in range(16)]
                ],
                [   # round 2
                    lambda B, C, D: (B & D) | (C & ~D),
                    [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12],
                    K[16:32],
                    [shifts[1][i % 4] for i in range(16)]
                ],
                [   # round 3
                    lambda B, C, D: B ^ C ^ D,
                    [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2],
                    K[32:48],
                    [shifts[2][i % 4] for i in range(16)]
                ],
                [   # round 4
                    lambda B, C, D: C ^ (B | ~D),
                    [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9],
                    K[48:64],
                    [shifts[3][i % 4] for i in range(16)]
                ]
            ]

            for (f, m_ind, k, s) in roundwise_values:
                for i in range(16):
                    # get the first word to process
                    m = int.from_bytes(block[m_ind[i] * 4: (m_ind[i] + 1) * 4], 'little')

                    # modular addition
                    result = (A + f(B, C, D) + m + k[i]) % (2**32)

                    # bit rotation
                    result = (result >> (32 - s[i])) | (result << s[i])

                    # more modular addition
                    result = (B + result) % (2**32)

                    A = result

                    # rotate the values of the initialisation vectors
                    A, B, C, D = D, A, B, C

            # add the initial values of the initialisation vectors
            A = (A + _A) % (2**32)
            B = (B + _B) % (2**32)
            C = (C + _C) % (2**32)
            D = (D + _D) % (2**32)

        # concatenate all the values
        return (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
                C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', type=str, required=True, help="Name of the file to find the checksum")

    args = parser.parse_args()
    try:
        with open(args.f, 'rb') as file:

            # Read the contents of the file
            file_contents = file.read()
            md5 = MD5()
            print(md5.generate_hash(file_contents).hex())
    except FileNotFoundError:
        logger.error("File does not exist")
