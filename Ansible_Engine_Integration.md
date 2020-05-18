# Ansible Engine Integration

### Introducción

* Ansible Engine gestiona máquinas Linux / UNIX utilizando SSH de forma predeterminada
* Alternativa para administrar máquinas Windows: use PowerShell nativo de forma remota
* Máquinas Windows administradas desde la máquina de control de Linux
* winrm Módulos de Python utilizados para hablar con máquinas Windows.
* Ansible Engine mantiene propiedades sin agente para administrar máquinas Windows
* No se necesita software adicional de Windows

### Preparando la máquina de control
Instalar pywinrm:

      pip install pywinrm

Configure la autenticación para administrar la máquina Windows
