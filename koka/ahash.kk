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