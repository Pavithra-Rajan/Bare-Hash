import logging
import math 
import argparse

logging.basicConfig(format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()

logger.setLevel(logging.DEBUG)


def get_nth_prime(n):
    """
    This function returns the nth prime number
    Args:
        n: The nth value
    """
    if n == 1:
        return 2
    elif n == 2:
        return 3
    else:
        count = 2 # the primes so far
        num = 3 # the 2nd odd prime 
        while count < n:
            num += 2    # skip by 2 for getting odd numbers
            # Generate odd nums >= 3 till sqrt of the number
            # Check if any of these give remainder 0 on division
            # If any is faslse, then not prime
            if all(num % i != 0 for i in range(3, int(math.sqrt(num))+1, 2)):
                count += 1
        return num

def fract_64_prime():
    """
    This function returns a list containing 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.
    """

    output = []

    for i in range(1, 65):
        prime = get_nth_prime(i)
        cube_root = round(prime**(1/3), 20)
        fractional_part = cube_root - int(cube_root)
        hexadecimal = int(fractional_part * 2**32)
        output.append(hexadecimal)
    return output

def fract_8_prime():
    """
    This function returns a list containing 32 bits of the fractional parts of the square roots of the first 8 prime numbers.
    """

    output = []

    for i in range(1, 9):
        prime = get_nth_prime(i)
        square_root = round(prime**(1/2), 20)
        fractional_part = square_root - int(square_root)
        hexadecimal = int(fractional_part * 2**32)
        output.append(hexadecimal)
    return output
K = fract_64_prime()
H = fract_8_prime()

def rotate_right(num, shift, size = 32):
    """
    This function rotates an integer to the right for a given number of shifts.
    The default size is 32 bits
    The rotate right (circular right shift) operation ROTRn(x), where x is a w-bit word and n is an integer with 0 <= n < w, is defined by
    ROTRn(x) = (x >> n) | (x << w - n)
    """
    return (num >> shift) | (num << size - shift)

def choice(x, y, z):
    """
    Returns the Ch(x, y, z) function defined in sec 4.1.2 func (4.2).
    Ch stands for choose or choice, as the x input chooses if the output is from y or from z. 
    More precisely, for each bit index, that result bit is according to the bit from y or respectively z at this index, depending on if the bit from x at this index is 1 (or respectively 0).
    """
    return (x & y) ^ (~x & z)

def majority(x: int, y: int, z: int):
    """
    Return the Maj(x, y, z) function as defined in sec 4.1.2 func (4.3).
    Maj stands for majority: for each bit index, that result bit is according to the majority of the 3 inputs bits for x, y and z at this index
    """
    return (x & y) ^ (x & z) ^ (y & z)

def big_sigma_0(num: int):
    """
    Returns the ∑0(x) function defined in sec 4.1.2 func (4.4).
    """
    num = (rotate_right(num, 2) ^
           rotate_right(num, 13) ^
           rotate_right(num, 22))
    return num

def big_sigma_1(num: int):
    """
    Returns the ∑1(x) function defined in sec 4.1.2 func (4.5).
    """
    num = (rotate_right(num, 6) ^
           rotate_right(num, 11) ^
           rotate_right(num, 25))
    return num

def small_sigma_0(num: int):
    """
    Returns the σ0(x) function defined in sec 4.1.2 func (4.6).
    """
    num = (rotate_right(num, 7) ^
           rotate_right(num, 18) ^
           (num >> 3))
    return num

def small_sigma_1(num: int):
    """
    Returns the σ1(x) function defined in sec 4.1.2 func (4.7).
    """
    num = (rotate_right(num, 17) ^
           rotate_right(num, 19) ^
           (num >> 10))
    return num

class SHA256:
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
        
    def generate_hash(self, message):
        """
        This function takes in the message and returns the SHA256 hash of it.
        Args:
            message: The message to be hashed via SHA256
        """

        #print(type(message))
        # Type checking and type casting accordingly
        if isinstance(message, str):
            message = bytearray(message, 'ascii')   # encode to bytearray object with ASCII format
        elif isinstance(message, bytes):
            message = bytearray(message)
        elif not isinstance(message, bytearray):
            raise TypeError

        padded_message = self.padding(message)
        blocks = self.parsing(padded_message)

        # Setting Initial Hash Value
        # Consists of eight 32-bit words in hex
        # They are obtained by taking the first 32-bits of the fractional parts of the square roots of the first eight prime numbers.
        h0 = H[0]
        h1 = H[1]
        h2 = H[2]
        h3 = H[3]
        h4 = H[4]
        h5 = H[5]
        h6 = H[6]
        h7 = H[7]

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', type=str, required=True, help="Name of the file to find the checksum")
    
    args = parser.parse_args()
    try:
        with open(args.f, 'rb') as file:
        
        # Read the contents of the file
            file_contents = file.read()
            sha256 = SHA256()
            print(sha256.generate_hash(file_contents).hex())
    except FileNotFoundError:
        logger.error("File does not exist")
        
        