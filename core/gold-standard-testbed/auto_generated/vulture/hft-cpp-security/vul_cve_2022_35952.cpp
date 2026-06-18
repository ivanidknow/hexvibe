// Vulnerable: VUL-CVE-2022-35952
const Tensor& batch_index_t = context->input(1);
    const Tensor& grad_t = context->input(2);

    mutex_lock ml(mu_);
...

    mutex_lock ml(mu_);

    const int64_t batch_key = context->input(3).scalar<int64_t>()();
...
      }
...


if __name__ == "__main__":
