multipass launch \
  --name lintap-dev \
  --cpus 4 \
  --memory 4G \
  --disk 50G \
  --timeout 900 \
  --cloud-init cloud-init-lintap.yaml \
  noble
