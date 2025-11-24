#!/usr/bin/env python3


from concurrent.futures import ThreadPoolExecutor

def funcion(x,y):
    print(x)
    print(f"Este es el valor de Y {y}")

lista = [1,2,3,4,5]
y = 2
with ThreadPoolExecutor() as e:
    e.map(lambda x: funcion(x,y),lista)