from src.individual.sphincskeygen import time_sign_verif, oqs_keygen

def example_benchmark():
    #Regenerate keys before running test sets. This is especially true if you have changed the algorithm.
    oqs_keygen()
    res = time_sign_verif()
    num_iterations = 50
    sign_times = res["sign_times"]
    verify_times = res["verify_times"]
    print(f"Average signing time:  {sum(sign_times) / num_iterations * 1000:.2f} ms")
    print(f"Average verify time:   {sum(verify_times) / num_iterations * 1000:.2f} ms")