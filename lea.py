from sha256 import logger, small_sigma_0, small_sigma_1, big_sigma_0, big_sigma_1, choice, majority, fract_64_prime, fract_8_prime
import argparse

K = fract_64_prime()
H = fract_8_prime()

class SHA256:
    def padding(self, message, length=None):
        """
        This function does the padding of the message so that it is a multiple of 512 bits.
        Step 1:
            Add a single "1" bit to the end of the message
        Step 2:
            Add a fixed number of "0"s to the end of the message. Let the number of 0s be k
            If l is the size of the message, then l + k + 1 mod 512 should be 64
        Step 3:
            Append 64 bit binary representation of l which is the length of the message

        Args:
            message: The message to be padded to a multiple of 512 bits
            length: Length to append at the end (in bytes)
        """

        if length is None:
            length = len(message) * 8 # len gives number of bytes so multiply by 8 to get bits

        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0:
            message.append(0x00)

        message += length.to_bytes(8, 'big') # Convert to bytes with big-endian format. MSB is first.
        #message.append(0x80) #To check if error is logged
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
        blocks = [] # contains 512-bit blocks of message
        for i in range(0, len(padded_message), 64): # 64 bytes is 512 bits
            blocks.append(padded_message[i:i+64])
        return blocks
    
    def generate_hash(self, message, initial_vector=H, length=None):
        """
        This function takes in the message and returns the SHA256 hash of it.
        Args:
            message: The message to be hashed via SHA256
            intial_vector: Intial hash value as eight 32-bit words in hex, defaults to32-bits of the fractional parts of the square roots of the first eight prime numbers
            length: length to be appended (in bits) when padding
        """

        # Type checking and type casting accordingly
        if isinstance(message, str):
            message = bytearray(message, 'ascii')   # encode to bytearray object with ASCII format
        elif isinstance(message, bytes):
            message = bytearray(message)
        elif not isinstance(message, bytearray):
            raise TypeError

        padded_message = self.padding(message, length=length)
        blocks = self.parsing(padded_message)

        h0 = initial_vector[0]
        h1 = initial_vector[1]
        h2 = initial_vector[2]
        h3 = initial_vector[3]
        h4 = initial_vector[4]
        h5 = initial_vector[5]
        h6 = initial_vector[6]
        h7 = initial_vector[7]

        # Hash Computation and message schedule generation
        for message_block in blocks:
            # Prepare message schedule as specified by NIST paper sec 6.2.2
            message_schedule = []
            for t in range(0, 64):
                if t <= 15:
                    # Add the t'th 32 bit word of the block
                    # Start from the leftmost word
                    # 4 bytes at a time
                    message_schedule.append(bytes(message_block[t*4:(t*4)+4]))
                else:
                    term1 = small_sigma_1(int.from_bytes(message_schedule[t-2], 'big'))
                    term2 = int.from_bytes(message_schedule[t-7], 'big')
                    term3 = small_sigma_0(int.from_bytes(message_schedule[t-15], 'big'))
                    term4 = int.from_bytes(message_schedule[t-16], 'big')

                    # append a 4-byte byte object
                    schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                    message_schedule.append(schedule)

            if len(message_schedule) != 64:
                logger.error("Length of message schedule block is not 8 bytes")
                exit(1)

            # Initialize working variables
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7

            # Iterate for t = 0 to 63
            for t in range(64):
                t1 = ((h + big_sigma_1(e) + choice(e, f, g) + K[t] +
                    int.from_bytes(message_schedule[t], 'big')) % 2**32)

                t2 = (big_sigma_0(a) + majority(a, b, c)) % 2**32

                h = g
                g = f
                f = e
                e = (d + t1) % 2**32
                d = c
                c = b
                b = a
                a = (t1 + t2) % 2**32

            # Compute intermediate hash value
            h0 = (a + h0) % 2**32
            h1 = (b + h1) % 2**32
            h2 = (c + h2) % 2**32
            h3 = (d + h3) % 2**32
            h4 = (e + h4) % 2**32
            h5 = (f + h5) % 2**32
            h6 = (g + h6) % 2**32
            h7 = (h + h7) % 2**32

        return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
                (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
                (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
                (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))
    
def calc_msg_ext(original_message,extension,key):
    """
        This function calculates the extended message
        Args:
            original_message: The original message that was to be hashed
            extension: additional component to be appended to the original message
            key: The symmetric key with sender and receiver
    """
    sha256 = SHA256()
    original_bytearray = sha256.padding(bytearray(key+original_message, 'ascii'))
    extension_bytearray = bytearray(extension, 'ascii')
    return str(original_bytearray+extension_bytearray)[12:-2]

def calc_msg_ext_hash(original_message,extension,key):
    """
        This function calculates the hash of the extended message
        Args:
            original_message: The original message that was to be hashed
            extension: additional component to be appended to the original message
            key: The symmetric key with sender and receiver
    """
    sha256 = SHA256()
    original_bytearray = sha256.padding(bytearray(key+original_message, 'ascii'))
    extension_bytearray = bytearray(extension, 'ascii')
    target_hash = sha256.generate_hash(original_bytearray+extension_bytearray).hex()
    return target_hash

def bytearray_to_int_list(byte_arr):
    """
        This function converts a bytearray into a list of length 8
        where each element is a 32-bit integer value

        Args:
            byte_arr: Bytearray to be converted to a list
    """
    state = []
    for i in range(0,32,4):
        state.append(int.from_bytes(byte_arr[i:i+4], "big"))
    return state

def calc_len_message(len_original_message,len_extension):
    """
        This function calculates the length of the extended message
        Args:
            len_original_message: The length of (original message + key) that was to be hashed
            len_extension: length of extension to be appended to the original message
    """
    num_blocks = int(len_original_message / 64) + 1
    return num_blocks*512 + len_extension*8

def length_extension_attack(org_hash, msg_len, extension):
    """
        This function calculates the hash of the extended message
        Args:
            org_hash: hash of original message (as bytearray)
            msg_len: length of the previous message len(original_message+key)
    """
    sha256 = SHA256()

    # (LEA attack) Generating the hash of extended block using the output from 
    # original message has as the intial vector
    initial_vector = bytearray_to_int_list(org_hash)
    ext_msg_len = calc_len_message(msg_len,len(extension))
    ext_hash = sha256.generate_hash(extension,initial_vector,ext_msg_len).hex()
    return ext_hash

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', type=str, required=True, help="Message to be hashed")
    parser.add_argument('-s', type=str, required=True, help="The secret shared by both sender and receiver")
    parser.add_argument('-e', type=str, required=True, help="The extension to the message")
    
    args = parser.parse_args()

    original_message = args.m
    extension = args.e
    key = args.s

    # Generating the hash of the original message
    sha256 = SHA256()
    org_hash = sha256.generate_hash(key+original_message)

    # (LEA attack) Generating the hash of extended block using the output from 
    # original message has as the intial vector
    ext_hash = length_extension_attack(org_hash, len(key+original_message), extension)

    # Generating the hash of the extending message for verification
    extended_msg = calc_msg_ext(original_message,extension,key)
    target = calc_msg_ext_hash(original_message,extension,key)

    print("Original Message to be hashed: {}".format(key+original_message))
    print("MAC for Original Message: {}\n".format(org_hash.hex()))
    print("--------------------------------------------------\n")
    print("Extended Message to be hashed: {}\n".format(extended_msg))
    print("MAC for Extended Message: {}".format(target))
    print("MAC for Extended Message with LEA attack: {}\n".format(ext_hash))
    print("--------------------------------------------------\n")

    if ext_hash == target:
        print("(LEA successfull) The two hashes are identical")
    else:
        print("(LEA unsuccessfull) The two hashes are NOT identical")

