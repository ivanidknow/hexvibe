// Vulnerable: VUL-CVE-2022-23595
device->tensorflow_cpu_worker_threads()->num_threads);

string allowed_gpus =
    flr->config_proto()->gpu_options().visible_device_list();
TF_ASSIGN_OR_RETURN(absl::optional<std::set<int>> gpu_ids,
                    ParseVisibleDeviceList(allowed_gpus));
client_options.set_allowed_devices(gpu_ids);

auto client = xla::ClientLibrary::GetOrCreateLocalClient(client_options);
