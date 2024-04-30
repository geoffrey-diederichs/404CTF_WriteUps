```console
> python3 solver.py 
Chargement...

Voici un circuit réversible aléatoire sur 3 bits. Donnez un circuit équivalent optimal dans le même format. Les bits de contrôle seront notés en premier.


{"gates": [["TOFFOLI", [0, 2, 1]], ["NOT", [2]], ["CNOT", [2, 0]], ["CNOT", [0, 1]], ["TOFFOLI", [0, 1, 2]], ["NOT", [0]], ["TOFFOLI", [1, 0, 2]], ["CNOT", [0, 1]]], "bits": 3}

150028 {"gates": [["TOFFOLI", [2, 0, 1]], ["CNOT", [2, 0]], ["CNOT", [0, 2]], ["CNOT", [1, 2]], ["NOT", [1]]], "bits": 3}
sent
Encore un !


{"gates": [["NOT", [2]], ["CNOT", [1, 0]], ["NOT", [0]], ["CNOT", [1, 2]], ["NOT", [1]], ["CNOT", [1, 0]], ["TOFFOLI", [2, 1, 0]], ["CNOT", [2, 1]]], "bits": 3}

8393 {"gates": [["NOT", [1]], ["CNOT", [1, 2]], ["TOFFOLI", [1, 2, 0]], ["CNOT", [2, 1]]], "bits": 3}
sent
Un autre !


{"gates": [["NOT", [2]], ["NOT", [2]], ["NOT", [2]], ["CNOT", [1, 0]], ["NOT", [0]], ["CNOT", [0, 2]], ["CNOT", [0, 1]], ["NOT", [0]]], "bits": 3}

2385 {"gates": [["CNOT", [1, 0]], ["NOT", [1]], ["CNOT", [0, 1]], ["CNOT", [0, 2]]], "bits": 3}
sent
Un dernier !


{"gates": [["TOFFOLI", [1, 2, 0]], ["NOT", [0]], ["NOT", [1]], ["TOFFOLI", [2, 1, 0]], ["CNOT", [1, 0]], ["CNOT", [2, 1]], ["NOT", [1]], ["TOFFOLI", [2, 1, 0]]], "bits": 3}

185 {"gates": [["CNOT", [1, 0]], ["TOFFOLI", [1, 2, 0]], ["CNOT", [2, 1]]], "bits": 3}
sent
Bravo ! Voici le flag : 404CTF{25c5ded941d24014ffcefa84a06bf859}
```
