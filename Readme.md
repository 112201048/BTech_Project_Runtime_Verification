# Tool


## Build Instructions

To build both executables (`sample` and `tool`), run:

```bash
make
```


## Example Usage

Let’s try an example with the LTL formula:  
`[] (a == 1 && b -> <> c)`

Run the following:

```bash
./tool sample '[] (a == 1 && b -> <> c)'
```

---

## Clean Up

To remove the generated executables, run:

```bash
make clean
```