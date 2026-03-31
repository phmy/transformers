import openfhe
import torch
import sys
# from datetime import datetime

def Linear(bias, x, weight, CryptoContext, keys):
    # torch.addmm(bias, A, B) — computes A @ B + bias
    if CryptoContext != None and keys != None:
        bias = bias.tolist()
        x = x.tolist()
        weight = weight.tolist()
        x = FheLinear(bias, x, weight, CryptoContext, keys)
        return torch.tensor(x, dtype=bias.dtype)
    else:
        x = torch.addmm(bias, x, weight)
        return x

def FheLinear(bias, A, B, CryptoContext, keys):
    # A: [m x k], B: [k x n], bias: [n]
    # computes A @ B + bias, returns list of lists [m x n]
    cc = CryptoContext
    m = len(A)
    k = len(A[0])
    n = len(B[0])

    result = []
    for i in range(m):
        cA = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(A[i]))
        row = []
        for j in range(n):
            col_B = [B[l][j] for l in range(k)]
            c_prod = cc.EvalMult(cA, cc.MakeCKKSPackedPlaintext(col_B))
            c_dot = cc.EvalSum(c_prod, k)
            c_result = cc.EvalAdd(c_dot, cc.MakeCKKSPackedPlaintext([bias[j]]))
            pt = cc.Decrypt(c_result, keys.secretKey)
            pt.SetLength(1)
            row.append(pt.GetRealPackedValue()[0])
        result.append(row)

    return result

def CreateCryptoContextAndKeys():
    mult_depth = 1
    scale_mod_size = 50
    batch_size = 4096

    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(scale_mod_size)
    parameters.SetBatchSize(batch_size)

    cc = openfhe.GenCryptoContext(parameters)
    cc.Enable(openfhe.PKESchemeFeature.PKE)
    cc.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    cc.Enable(openfhe.PKESchemeFeature.ADVANCEDSHE)
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)
    return cc, keys