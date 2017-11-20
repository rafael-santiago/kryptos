#include <kryptos.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    kryptos_u8_t *domain_params = (kryptos_u8_t *)"-----BEGIN DH PARAM P-----\n"
                                                  "VSsW7ufPMgFn+MceQyQHgBtpq/q/"
                                                  "xLAZ00q/hRh8Of7Wvto1lsS6iBWs"
                                                  "mz4mYiSiOiPZkv6asUoBF8JhxMs4"
                                                  "LHEGaTV0uiRzIPxOABkXDGUnXjwd"
                                                  "EfpwkG3H+EuZK9fINggkkS+cxJ+P"
                                                  "DwkaoMgpwZEZj+ieeeOSnZgKuvaN"
                                                  "pVQ=\n"
                                                  "-----END DH PARAM P-----\n"
                                                  "-----BEGIN DH PARAM Q-----\n"
                                                  "Xdy01wlOrsxucvEv7bz+7VBT9X0=\n"
                                                  "-----END DH PARAM Q-----\n"
                                                  "-----BEGIN DH PARAM G-----\n"
                                                  "PdxLwCCBNeXR4EnVZb30SOHClBpr"
                                                  "bfJkZs3WHyct4mbI71Yo6tqFLXZZ"
                                                  "ozZCnP9ijWpsfz9qsfrcifcixEb0"
                                                  "Ewd+Xf3ne3sHVrFwC/VLCAAi1Ccc"
                                                  "a4GqzyO5juyIdjn2Bx8hWvV4E0G0"
                                                  "jgP58tlcjSNYP2lJj7TGafmyom44"
                                                  "Zxg=\n"
                                                  "-----END DH PARAM G-----\n";
    int exit_code = 0;

    printf("I'm verifying the following DH domain parameters...\n\n%s\n", domain_params);

    printf("Wait...\n");

    if (kryptos_dh_verify_domain_params(domain_params, strlen((char *)domain_params)) == kKryptosSuccess) {
        printf("INFO: The domain parameters are valid!\n");
    } else {
        printf("ERROR: Invalid domain parameters!\n");
        exit_code = 1;
    }

    return exit_code;
}
