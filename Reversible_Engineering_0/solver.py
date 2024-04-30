import socket
import json

HOST = "challenges.404ctf.fr"
PORT = 32274

BASE = {
        "gates": [],
        "bits": 3
}

ENTRIES = [[False, False, False], [True, False, False], [True, True, False], [True, True, True], [True, False, True], [False, True, False], [False, True, True], [False, False, True]]

MSG = '{"gates": [["NOT", [2]], ["NOT", [0]], ["CNOT", [0, 2]], ["TOFFOLI", [1, 2, 0]], ["NOT", [2]], ["CNOT", [2, 0]], ["NOT", [2]], ["NOT", [0]]], "bits": 3}'

def toff(entry: [bool], target: int) -> [bool]:
    solu = [entry[0], entry[1], entry[2]] # redeclaring the array not to modify entry
    if solu[(target+1)%3] and solu[(target+2)%3]:
        solu[target] = not solu[target]
    return solu

def cnot(entry: [bool], control: int, target: int) -> [bool]:
    solu = [entry[0], entry[1], entry[2]] # same
    if solu[control]:
        solu[target] = not solu[target]
    return solu

def lnot(entry: [bool], target: int) -> [bool]:
    solu = [entry[0], entry[1], entry[2]] # same
    solu[target] = not solu[target]
    return solu

def extrddact(message: str) -> dict:
    return json.loads(message)

def solve(circuit: dict, entry: [bool]) -> [bool]:
     solu = [entry[0], entry[1], entry[2]] # same                      
     for i in circuit["gates"]:
        if "NOT" == i[0]:
            solu = lnot(solu, i[1][0])
        elif "CNOT" == i[0]:
            solu = cnot(solu, i[1][0], i[1][1])
        elif "TOFFOLI" == i[0]:
            solu = toff(solu, i[1][2])
     return solu

def genCircuits(circuits) -> [dict]:
    newCirc = []
    for k in circuits:
        currCirc = json.loads(k)
        currCirc["gates"].append([])
        l = len(currCirc["gates"])-1
        for i in range(3):
            currCirc["gates"][l] = ["NOT", [i]]
            newCirc.append(json.dumps(currCirc))
            for k in range(1, 3):
                currCirc["gates"][l] = ["CNOT", [(i+k)%3, i]]
                newCirc.append(json.dumps(currCirc))
            currCirc["gates"][l] = ["TOFFOLI", [(i+1)%3, (i+2)%3, i]]
            newCirc.append(json.dumps(currCirc))
    return newCirc

def findEquivalent(circuits: [dict], prob_solu) -> int:
    for i in range(len(circuits)):
        solu = []
        for k in ENTRIES:
            solu.append(solve(json.loads(circuits[i]), k))
        if solu == prob_solu:
            return i 
    return -1

def solveProblem(problem: dict) -> str:
    probSolu = []
    for i in ENTRIES:
        probSolu.append(solve(problem, i))
    
    circuits = [json.dumps(BASE)]
    for i in range(8):
        circuits = genCircuits(circuits)
        resp = findEquivalent(circuits, probSolu)
        if resp != -1:
            print(resp, circuits[resp])
            return circuits[resp]


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        while True:
            data = s.recv(1024)
            print(data.decode("utf-8"))
            if b"gates" in data:
                data = data.split(b"\n")
                data = data[len(data)-2]
                problem = json.loads(data.decode("utf-8"))

                solution = solveProblem(problem)
                s.send(solution.encode()+b"\n")
                print("sent")
            elif b"flag" in data:
                exit()


        """
        probSolu = []
        for i in ENTRIES:
            probSolu.append(solve(problem, i))
    
        circuits = [json.dumps(BASE)]
        for i in range(8):
            circuits = genCircuits(circuits)
            resp = findEquivalent(circuits, probSolu)
            if resp != -1:
                s.send(circuits[resp].encode()+b"\n")
                print(resp, circuits[resp])
                data = s.recv(1024)
                while True:
                    print(data.decode("utf-8"))
                    data = s.recv(1024)
        """


if __name__ == "__main__":
    main()

    """
    problem = extract(MSG)
    probSolu = []
    for i in ENTRIES:
        probSolu.append(solve(problem, i))
    
    circuits = [json.dumps(BASE)]
    for i in range(8):
        circuits = genCircuits(circuits)
        resp = findEquivalent(circuits, probSolu)
        if resp != -1:
            print(resp, circuits[resp])
            exit()
    """
