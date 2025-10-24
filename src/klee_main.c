#include "local/linux/bpf_verifier.h"
#include <klee/klee.h>

extern int do_check(struct bpf_verifier_env *env);

int main() {
    struct bpf_verifier_env env;
    klee_make_symbolic(&env, sizeof(env), "env");
    int err = do_check(&env);
    return err;
}
