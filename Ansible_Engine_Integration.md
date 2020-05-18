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

### Preparación de la máquina de control: opciones de autenticación

#### Certificado
* Similar a SSH
* Certificado asignado al usuario local
* Certificado utilizado en lugar de contraseña para autenticar

#### Kerberos
* Necesita instalar el python-kerberos módulo en el host de control de Ansible Engine

#### CredSSP
* Se puede usar para autenticar con cuentas de dominio y locales

Protocolo de autenticación que admite la delegación de credenciales necesaria para la interacción con el recurso remoto / proceso en ejecución que requiere que las credenciales se almacenen en la sesión actual

### Preparación de la máquina de control: permisos y requisitos

Cuando se conecta a un host de Windows, hay varias opciones diferentes que pueden usarse para autenticarse con una cuenta. El tipo de autenticación se puede establecer en hosts de inventario o grupos con la **ansible_winrm_transport** variable.

La autenticación básica es una de las opciones de autenticación más simples de usar, pero también es la más insegura. Esto se debe a que el nombre de usuario y la contraseña están simplemente codificados en base64. La autenticación básica solo se puede usar para cuentas locales.

La autenticación de certificado utiliza certificados como claves, similares a los pares de claves SSH, pero el formato de archivo y el proceso de generación de claves son diferentes.

NT LAN Manager, o NTLM, es un mecanismo de autenticación más antiguo utilizado por Microsoft que puede admitir cuentas locales y de dominio. NTLM está habilitado en el servicio WinRM de forma predeterminada, por lo que no se requiere configuración antes de usarlo. NTLM es el protocolo de autenticación más fácil de usar y es más seguro que la autenticación básica.

Kerberos es la opción de autenticación recomendada para usar cuando se ejecuta en un entorno de dominio. Kerberos admite características como la delegación de credenciales y el cifrado de mensajes a través de HTTP y es una de las opciones más seguras disponibles a través de WinRM.

La autenticación CredSSP es un protocolo de autenticación más nuevo que permite la delegación de credenciales. Esto se logra encriptando el nombre de usuario y la contraseña después de que la autenticación haya sido exitosa y enviándola al servidor usando el protocolo CredSSP.



### Preparando la máquina de Windows
* Se necesita PowerShell 3.0 o superior para la mayoría de los módulos de Ansible Engine para Windows
* Habilitar PowerShell
* PowerShell Script se puede usar para automatizar la instalación de WinRM
https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
* ConfigureRemotingForAnsible.ps1 escribe cada cambio que realiza en el registro de eventos de Windows
* Útil para solucionar problemas

### Preparación de la máquina de Windows: configuraciones
* Las máquinas con Windows se pueden configurar con un script o una herramienta de orquestación

Ejemplo: secuencia de comandos UserData:

      <powershell> \ n 
      $ admin = [adsi] ('WinNT: //./administrator, user') \ n 
      $ admin.PSBase.Invoke ('SetPassword', 'jVMijRwLbI02gFCo2xkjlZ9lxEA7bm7zgg ==') \ n 
      $ scriptPath = (( New-Object System.Net.Webclient) .DownloadString ('https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1')) 
      Invoke-Command -ScriptBlock ([scriptblock] :: Crear ($ scriptPath)) -ArgumentList '-skipNetworkProfileCheck' \ n 
      </powershell>
      

### Configuración Kerberos
* Cuando se usa una cuenta de Active Directory, Kerberos prefiere a NTLM

Instalar dependencias de Kerberos:

      yum -y install python-devel krb5-devel krb5-libs krb5-workstation

Instalar python-kerberos:

      pip install pywinrm[kerberos]

### Configuración de Kerberos: información de dominio
Agregue información para cada dominio para conectarse:


      # cat /etc/krb5.conf.d/ansible.conf

      [realms]

       ad1.${GUID}.example.opentlc.com = {

       kdc = ad1.${GUID}.example.opentlc.com
       }

      [domain_realm]
       .ad1.${GUID}.example.opentlc.com = ad1.${GUID}.EXAMPLE.OPENTLC.CO
NOTA: Este archivo distingue entre mayúsculas y minúsculas.

### Configuración de Kerberos: prueba
La sección de dominio debe estar completamente calificada:

      # kinit bill@ad1.${GUID}.example.opentlc.com
      Password for bill@ad1.${GUID}.example.opentlc.com:

      # klist
      Ticket cache: KEYRING:persistent:0:0
      Default principal: bill@ad1.${GUID}.EXAMPLE.OPENTLC.COM

      Valid starting       Expires              Service principal
      10/02/2017 18:44:16  10/03/2017 04:44:16  krbtgt/ad1.${GUID}.EXAMPLE.OPENTLC.COM@ad1.${GUID}.EXAMPLE.OPENTLC.COM
            renew until 10/03/2017 18:44:11       

# Inventario
* Ansible Engine utiliza variables estándar para indicar el nombre de usuario, la contraseña y el tipo de conexión de la máquina Windows

Ejemplo de archivo de inventario:

      vi /etc/ansible/hosts
      [windows]
      ## These are the windows servers
      windows1.${GUID}.internal
      [windows:vars]
      ansible_connection=winrm
      ansible_user=Administrator
      ansible_winrm_server_cert_validation=ignore
      ansible_become=false

### Hechos de Windows
* Se pueden recopilar datos para los hosts de Windows
*Similar a Linux / UNIX:

      # ansible windows1.${GUID}.internal
      ...Output Omitted
      ansible_kernel": "6.3.9600.0",
              "ansible_lastboot": "2017-10-02 20:44:56Z",
              "ansible_machine_id": "S-1-5-21-2650452223-3484426441-1752233355",
              "ansible_memtotal_mb": 8192,
              "ansible_nodename": "WIN-2127KNJOQ65.ad1.${GUID}.example.opentlc.com",
              "ansible_os_family": "Windows",
              "ansible_os_name": "Microsoft Windows Server 2012 R2 Standard"
      ...Output Omitted...
      
### Módulos de Windows
* Módulos de Core Ansible Engine escritos para la combinación de:
* Máquinas Linux / UNIX
* Servicios web arbitrarios
* Varios módulos de Windows también disponibles:
* http://docs.ansible.com/ansible/latest/list_of_windows_modules.html 
* En muchos casos, no se necesita el módulo Ansible Engine
* En particular, puede usar el scriptmódulo para ejecutar scripts arbitrarios de PowerShell
* Admite administradores de Windows familiarizados con PowerShell      

### Módulos de Windows: conectividad
* Para verificar la conectividad:

      - hosts: all
        tasks:
        - name: Check Windows server
          win_ping:
          when: ansible_distribution == "Microsoft Windows Server 2012 R2 Standard"
        - name: Check Linux servers
          ping:
          when: ansible_distribution != "Microsoft Windows Server 2012 R2 Standard"
          
# Módulos de Windows: descripciones

### win_chocolatey
* Administrar paquetes usando Chocolatey
* Administre fácilmente todos los aspectos del software de Windows: instalación, configuración, actualización, desinstalación
* Para obtener una lista de los paquetes, vaya al "Repositorio de paquetes de Chocolatey ^"

### win_service
* Administrar servicios de Windows

### win_firewall
* Habilitar / deshabilitar Firewall de Windows

### win_firewall_rule
* Permitir crear / eliminar / actualizar reglas de firewall

### win_user
Administrar cuentas de usuario locales de Windows

### win_domain_user
* Administrar cuentas de usuario de Windows Active Directory
* Requiere Ansible Engine versión 2.4

### win_domain_controller
* Administrar el controlador de dominio / estado del servidor miembro para el host de Windows

## Agregar una regla de firewall
Para agregar una regla de firewall, use el win_firewall_rule módulo. Un ejemplo se muestra aquí.

      - name: Add win_firewall_rule
        win_firewall_rule:
          name: SSHD
          localport: 22
          action: allow
          direction: in
          protocol: tcp
          state: present
          enabled: yes

### Agregar un usuario de Windows Active Directory
Para agregar un usuario de Windows AD, use el win_domain_usermódulo. Un ejemplo se muestra aquí.

      # tasks file for roles/win_ad_user
      - name: Create AD User
        win_domain_user:
          name: "{{ item.name }}"
          firstname: "{{ item.firstname }}"
          surname: "{{ item.surname }}"
          password: "{{ item.password }}"
          state: present
          email: '"{{ item.name }}"@ad1.{{ GUID }}.example.opentlc.com'
        loop: "{{ user_info }}"

### Conclusión
* El soporte de Windows en Ansible Engine todavía es relativamente nuevo
* WinRM y PowerShell son importantes
* Inventario de variables necesarias para administrar con éxito los hosts de Windows
* No todos los módulos de Windows comienzan con win_*
* Algunos módulos principales, complementos de acción funcionan con Windows:
* include_role
* include_vars
* set_fact
* setup

Ansible Engine puede administrar hosts de Windows, pero el soporte de Windows en Ansible Engine todavía es relativamente nuevo. WinRM y PowerShell son componentes importantes para integrar Ansible Engine con Windows.

Las variables de inventario deben configurarse para administrar correctamente los hosts de Windows.

No todos los módulos de Windows comienzan con win_*. Algunos módulos básicos y de acción plug-ins que funciona con Windows incluyen include_role, include_vars, set_fact, y setup.




Paquetes adiconales para bastion.
      
      [root@bastion 0 ~]# yum -y install python-devel krb5-devel krb5-libs krb5-workstation python-pip gcc
      [root@bastion 0 ~]# pip install "pywinrm>=0.2.2"

Validar con ping.

      [root@bastion 0 ~]# ansible windows -m win_ping
      ad1.5a16.internal | SUCCESS => {
          "changed": false, 
          "ping": "pong"
      }
      [root@bastion 0 ~]# 


Archivo de configuración (hosts)

      [root@bastion 0 ~]# cat /etc/ansible/hosts
      [all:vars]
      timeout=60
      ansible_become=yes
      ansible_user=ec2-user

      [all:children]
      support
      windows

      [support]
      support1.5a16.internal ssh_host=support1.5a16.internal

      [windows]
      ad1.5a16.internal ssh_host=ad1.5a16.example.opentlc.com ansible_password=jVMijRwLbI02gFCo2xkjlZ9lxEA7bm7zgg==

      [windows:vars]
      ansible_connection=winrm
      ansible_user=Administrator
      ansible_winrm_server_cert_validation=ignore
      ansible_become=false
      [root@bastion 0 ~]# 



      

