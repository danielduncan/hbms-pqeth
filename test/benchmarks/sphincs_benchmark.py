from src.individual.sphincskeygen import time_sign_verif, oqs_keygen
import oqs
import csv

variants = ['SPHINCS+-SHA2-128f-simple', 'SPHINCS+-SHA2-128s-simple', 'SPHINCS+-SHA2-192f-simple', 'SPHINCS+-SHA2-192s-simple', 'SPHINCS+-SHA2-256f-simple', 'SPHINCS+-SHA2-256s-simple']

def example_benchmark(algo):
    #Regenerate keys before running test sets. This is especially true if you have changed the algorithm.
    oqs_keygen(algo)

    res = time_sign_verif(algo)
    num_iterations = 50
    sign_times = res["sign_times"]
    verify_times = res["verify_times"]
    sign_length = res['length']
    sk_length = res['sk_len']
    pk_length = res['pk_len']
    print(f"Average signing time:  {sum(sign_times) / num_iterations * 1000:.2f} ms")
    print(f"Average verify time:   {sum(verify_times) / num_iterations * 1000:.2f} ms")
    return [algo, sum(sign_times) / num_iterations * 1000, sum(verify_times) / num_iterations * 1000, sign_length,sk_length,pk_length]


with open('sphincs_res.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    results_list = [['algorithm name','sign time', 'verify time', 'signature length', 'secret key length', 'public key length']]
    for kem in variants:
        results_list.append(example_benchmark(kem))
    writer.writerows(results_list)
        
