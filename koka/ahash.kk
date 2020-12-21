include extern {
  c  file "ahash_koka.c"
}

type hasher
type random-state


extern ahash_version() : string {
  c inline "kk_ahash_version()"
}

extern reinit-global-state() : ndet () {
  c inline "reinitialize_global_seed(kk_context())"
}

extern next-state() : ndet random-state {
  c inline "next_random_state(kk_context())"
}

extern seed-state(seed: int32) : random-state {
  c inline "seed_state((#1), kk_context())"
}

extern hasher(state: random-state) : hasher {
  c inline "create_hasher((#1), kk_context())"
}

extern finish(h: hasher) : int {
  c inline "kk_hasher_finish((#1), kk_context())"
}

extern write(h: hasher, x: int) : hasher {
  c inline "kk_hasher_write_int((#1), (#2), kk_context())"
}

extern write(h: hasher, x: string) : hasher {
  c inline "kk_hasher_write_str((#1), (#2), kk_context())"
}

extern write(h: hasher, x: int32) : hasher {
  c inline "kk_hasher_write_int32_t((#1), (#2), kk_context())"
}

extern write(h: hasher, x: int16) : hasher {
  c inline "kk_hasher_write_int16_t((#1), (#2), kk_context())"
}

extern write(h: hasher, x: int8) : hasher {
  c inline "kk_hasher_write_int8_t((#1), (#2), kk_context())"
}

extern write(h: hasher, x: uint8) : hasher {
  c inline "kk_hasher_write_uint8_t((#1), (#2), kk_context())"
}

extern write(h: hasher, x: size_t) : hasher {
  c inline "kk_hasher_write_size_t((#1), (#2), kk_context())"
}

extern write(h: hasher, x: char) : hasher {
  c inline "kk_hasher_write_kk_char_t((#1), (#2), kk_context())"
}

fun write(h: hasher, x: list<int>) : hasher {
  x.foldl(h, write)
}

fun write(h: hasher, x: list<string>) : hasher {
  x.foldl(h, write)
}

fun write(h: hasher, x: list<int32>) : hasher {
  x.foldl(h, write)
}

//fun write(h: hasher, x: list<int8>) : hasher {
//  x.foldl(h, write)
//}

//fun write(h: hasher, x: list<uint8>) : hasher {
//  x.foldl(h, write)
//}

//fun write(h: hasher, x: list<int16>) : hasher {
//  x.foldl(h, write)
//}

fun write(h: hasher, x: list<char>) : hasher {
  x.foldl(h, write)
}

fun single(state: random-state, x: int) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: string) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: int32) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: int16) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: int8) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: uint8) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: size_t) : int {
  state.hasher.write(x).finish
}

fun single(state: random-state, x: char) : int {
  state.hasher.write(x).finish
}

