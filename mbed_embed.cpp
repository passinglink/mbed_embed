#if defined(__LP64__)
#error You probably want to build this in 32-bit mode.
#endif

#undef _NDEBUG
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <type_traits>
#include <vector>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "provisioning_types.h"

struct Partition {
  explicit Partition(uint32_t begin_address, uint32_t partition_size)
      : begin_address_(begin_address), current_offset_(0), partition_size_(partition_size) {
    // TODO: Assert that we start on a reasonable alignment boundary.
    data_.reserve(partition_size);
  }

  uint32_t size() const { return data_.size(); }
  const void* data() const { return data_.data(); }

  void build(ProvisioningVersion version, std::string board_name, const char serial[16],
             const char signature[256], mbedtls_rsa_context* rsa_context) {
    ProvisioningData* pd = allocate<ProvisioningData>(1);
    pd->version = version;
    assert(board_name.size() < sizeof(pd->board_name));
    strcpy(pd->board_name, board_name.c_str());

    PS4Key* ps4_key = allocate<PS4Key>(1);
    pd->ps4_key = to_flash(ps4_key);
    memcpy(ps4_key->serial, serial, sizeof(ps4_key->serial));
    memcpy(ps4_key->signature, signature, sizeof(ps4_key->signature));

    ps4_key->rsa_context = clone(rsa_context);
    assert(partition_size_ >= data_.size());
  }

 private:
  // Returns a to_flash'ed pointer to a copied mbedtls_rsa_context.
  mbedtls_rsa_context* clone(const mbedtls_rsa_context* rsa) {
    mbedtls_rsa_context* result = allocate<mbedtls_rsa_context>(1);

    // Fields to copy directly.
    result->ver = rsa->ver;
    result->len = rsa->len;
    result->padding = rsa->padding;
    result->hash_id = rsa->hash_id;

    // mbedtls_mpi fields:
    result->N = clone(rsa->N);
    result->E = clone(rsa->E);
    result->D = clone(rsa->D);
    result->P = clone(rsa->P);
    result->Q = clone(rsa->Q);
    result->DP = clone(rsa->DP);
    result->DQ = clone(rsa->DQ);
    result->QP = clone(rsa->QP);
    result->RN = clone(rsa->RN);
    result->RP = clone(rsa->RP);
    result->RQ = clone(rsa->RQ);
    result->Vi = clone(rsa->Vi);
    result->Vf = clone(rsa->Vf);
    return to_flash(result);
  }

  mbedtls_mpi clone(mbedtls_mpi mpi) {
    mbedtls_mpi result;
    result.s = mpi.s;
    result.n = mpi.n;

    if (mpi.p) {
      mbedtls_mpi_uint* p = allocate<mbedtls_mpi_uint>(mpi.n);
      memcpy(p, mpi.p, sizeof(*p) * mpi.n);
      result.p = to_flash(p);
    }
    return result;
  }

  template <typename T>
  T* to_flash(T* p) {
    uintptr_t offset = reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(data_.data());
    return reinterpret_cast<T*>(begin_address_ + offset);
  }

  uint32_t align(uint32_t addr, size_t alignment) {
    uint32_t mask = (1 << alignment) - 1;
    if (addr & mask) {
      addr += (1 << alignment) - (addr & mask);
    }
    return addr;
  }

 public:
  template <typename T>
  T* allocate(size_t count) {
    static_assert(std::is_trivially_destructible_v<T>);

    current_offset_ = align(current_offset_, alignof(T));
    data_.resize(current_offset_ + count * sizeof(T));

    T* p = reinterpret_cast<T*>(&data_[current_offset_]);
    current_offset_ = data_.size();
    return p;
  }

 private:
  uint32_t begin_address_;
  uint32_t current_offset_;
  uint32_t partition_size_;

  std::vector<char> data_;
};

static uint32_t parse_u32(const char* arg) {
  char* end;
  if (*arg == '\0') {
    errx(1, "empty argument");
  }

  long long result = strtoll(arg, &end, 0);
  if (*end != '\0' || result < 0 || result > UINT32_MAX) {
    errx(1, "invalid argument: '%s'", arg);
  }
  return result;
}

int main(int argc, char** argv) {
  if (argc != 7) {
    errx(1, "usage: mbed_embed PARTITION_BEGIN PARTITION_SIZE BOARD_NAME PRIVATE_KEY_DER SERIAL SIGNATURE");
  }

  uint32_t partition_begin = parse_u32(argv[1]);
  uint32_t partition_size = parse_u32(argv[2]);
  const char* board_name = argv[3];

  unsigned char der_buf[4096];
  size_t der_len;
  {
    FILE* f = fopen(argv[4], "r");
    if (!f) {
      err(1, "failed to open '%s'", argv[1]);
    }

    der_len = fread(der_buf, 1, sizeof(der_buf), f);
    if (der_len == 0) {
      errx(1, "failed to read from '%s'", argv[1]);
    }

    fclose(f);
  }

  char serial_buf[17];
  {
    FILE* f = fopen(argv[5], "r");
    if (!f) {
      err(1, "failed to open '%s'", argv[2]);
    }

    size_t len = fread(serial_buf, 1, sizeof(serial_buf), f);
    if (len != 16) {
      err(1, "failed to read from '%s': got %zu bytes", argv[2], len);
    }

    fclose(f);
  }

  char signature_buf[257];
  {
    FILE* f = fopen(argv[6], "r");
    if (!f) {
      err(1, "failed to open '%s'", argv[3]);
    }

    size_t len = fread(signature_buf, 1, sizeof(signature_buf), f);
    if (len != 256) {
      err(1, "failed to read from '%s': got %zu bytes", argv[3], len);
    }

    fclose(f);
  }

  mbedtls_pk_context pk_ctx;
  mbedtls_pk_init(&pk_ctx);

  int rc = mbedtls_pk_parse_key(&pk_ctx, der_buf, der_len, nullptr, 0);
  if (rc != 0) {
    errx(1, "failed to parse key");
  }

  if (mbedtls_pk_get_type(&pk_ctx) != MBEDTLS_PK_RSA) {
    errx(1, "invalid key format");
  }

  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk_ctx);
  if (mbedtls_rsa_complete(rsa) != 0) {
    errx(1, "failed to complete RSA key");
  }

  // Populate RN.
  mbedtls_mpi temp;
  mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&rsa->RN);
  if (mbedtls_mpi_exp_mod(&temp, &rsa->E, &rsa->E, &rsa->N, &rsa->RN) != 0) {
    errx(1, "failed to populate RN");
  }

  rsa->padding = MBEDTLS_RSA_PKCS_V21;
  rsa->hash_id = MBEDTLS_MD_SHA256;

  Partition p(partition_begin, partition_size);
  p.build(ProvisioningVersion::V1, board_name, serial_buf, signature_buf, rsa);
  fwrite(p.data(), p.size(), 1, stdout);
}
