import ahash
import std/time/timer
import std/num/random
fun bench-hash-string(str: string, count: int, last: int) : <div, ndet> () {
    if (count <= 0) then ()
    else {
        val state = next-state()
        bench-hash-string(str, count - 1, state.single(str) + last)
    }
}

fun bench-hash-int(data: int, count: int) : <div, ndet> () {
    if (count <= 0) then ()
    else {
        val state = next-state()
        bench-hash-int(data +  state.single(data), count - 1)
    }
}

fun bench-hash-list(data: list<char>, count: int, last: int) : <div, ndet> () {
    if (count <= 0) then ()
    else {
        val state = next-state()
        bench-hash-list(data, count - 1, last + state.hasher.write(data).finish)
    }
}

fun bench-hash-int32(data: int32, count: int) : <div, ndet> () {
    if (count <= 0) then ()
    else {
        val state = next-state()
        bench-hash-int32(state.single(data).int32, count - 1)
    }
}

fun random-string(current: list<int>, length: int) : div string {
    if (length < 0)
    then current.show
    else random-string(Cons(length, current), length - 1)
}
fun main() {
    println("Ahash Version: " + ahash-version())
    val data = random-string(Nil, 1000)
    println("benchmark hashing string with length: " + data.list.length.show)
    print-elapsed( { bench-hash-string(data, 1000000, 0) } )
    val int-data = 0xffffffffffffffffffffffffffffffffffffffffffffff 
        + random-int() * random-int() * random-int() 
        * random-int() * random-int() * random-int() 
        * random-int() * random-int() * random-int() 
    println("benchmark hashing int with data: " + int-data.show)
    print-elapsed( { bench-hash-int(int-data, 1000000) } )

    println("benchmark hashing int32 (small data): ")
    print-elapsed( { bench-hash-int32(int-data.int32, 1000000) } )

    println("benchmark hashing char list: ")
    print-elapsed( { bench-hash-list(data.list, 1000000, 0) } )
    
}