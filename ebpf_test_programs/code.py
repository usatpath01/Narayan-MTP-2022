a=[]
x=4
y=60
for i in range(x):
    b=[]
    for j in range(y):
        t=input()
        b.append(t)
    a.append([ f-b[0] for f in b])

for i in range(y):
    print([ a[f][i] for f in range(x)])