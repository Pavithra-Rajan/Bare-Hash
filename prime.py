import math

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
        hexadecimal = hex(int(fractional_part * 2**32))
        output.append(hexadecimal)
    return output

#fract_64_prime()

