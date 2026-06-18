// Vulnerable: VUL-CVE-2022-2652
strlcpy(cap->driver, "v4l2 loopback", sizeof(cap->driver));
	snprintf(cap->card, labellen, dev->card_label);
	snprintf(cap->bus_info, sizeof(cap->bus_info),
		 "platform:v4l2loopback-%03d", device_nr);
...

	MARK();
	snprintf(dev->vdev->name, sizeof(dev->vdev->name), dev->card_label);

	vdev_priv->device_nr = nr;
