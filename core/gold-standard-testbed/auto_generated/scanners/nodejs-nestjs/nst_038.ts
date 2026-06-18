// Vulnerable: NST-038
enqueueSnackbar('Registration success, Please verify your email', {
  variant: 'success',
  action: key => (
    <MIconButton size="small" onClick={() => closeSnackbar(key)}>
      <Icon icon={closeFill} />
    </MIconButton>
  ),
});
