---
tags:
  - ldap3
  - python
---
# Операция Bind

Как указано в RFC4511 операция **Bind** это операция "аутентификации". Она (и операция [[UNBIND]] так же) получила это имя по историческим причинам.

Когда вы открываете подключение к LDAP серверу, вы в состоянии **анонимного** подключения. Что это точно означает определяется реализацией сервера, не протоколом. Думайте об этом как о публичном доступе к серверной информации (даже то, что означают публичные данные определяет сервер). В [[ldap3]] вы создаете подключение к серверу через метод `open()` объекта [[Connection|connection]]. Метод `bind()` откроет подключение если оно еще не открыто.

Операция Bind позволяет учетным данным быть обмененными между клиентом и сервером для создания нового авторизационного состояния.

Запрос Bind обычно указывает желаемый идентификатор аутентификации. Некоторые Bind механизмы также позволяют клиенту указать идентификатор авторизации. Если идентификатор авторизации не указан, сервер получает его из идентификатора аутентификации определенно-реализованным способом. 

Если вы хотите предоставить аутентификационную информацию, вы должны использовать операцию Bind что бы указать идентификатор, который будет использоваться доступа к данным. Имейте в виду, что данные аутентификации, а не данные авторизации являются данными локального сервера. LDAP протокол не указывает как идентификатор должен храниться на сервере, ни как указываются авторизационные ACL'и.

Операция Bind указывает 4 разных метода аутентификации на сервере, как и указано в RFC4513:

- [[#Simple bind]]: вы предоставляете учетные данные означающие username (в форме DN (_distinguished name_)) и password ^9d757b
- [[#Anonymous Bind]]: username и password отправляются как пустые строки
- Unauthenticated simple Bind: Вы отправляете username без password. Этот метод, даже если указан в протоколе, не следует использовать, из-за критичной небезопасности и должен быть заблокирован сервером. Он был использован в прошлом для целей трассировки.
- [[#SASL]] (Simple Authentication and Security Layer): Определяет несколько механизмов, которые каждый сервер может предоставить для доступа. Перед использованием механизма вы должны проверить какой поддерживается сервером. Сервер LDAP публикует свои доступные SALS механизмы в DSE информации, которая может быть прочитана анонимно с параметром `get_info=ALL` [[Server]] объекта. ^3458eb

Метод Bind возвращает `True` если bind успешен, `False` если что-то пойдет не так. В этом случае, вы можете исследовать атрибут `result` объекта [[Connection|connection]] для получения описания ошибки.

## Simple bind

^a37f4c

Вы выполняете операцию Simple Bind как в следующем примере (используя стандартную синхронную стратегию):

``` python

# Импорт классов и констант
from ldap3 import Server, Connection, ALL

# Определение объекта сервера
s = Server(
    'servername',
    # Определение не безопасного LDAP сервера, запрос информации о DSE и схеме
    get_info=ALL
    )  

# Определение объекта подключения
c = Connection(
    s,
    user='user_dn',
    password='user_password'
    )

# Выполнение операции Bind
if not c.bind():
    print(
        'error in bind',
        c.result
        )

```

Объекты [[Server]] и [[Connection|connection]] созданы с использованием стандартных параметров:

``` python

s = Server(
    host='servername',
    port=389,
    use_ssl=False,
    get_info='ALL'
    )
c = Connection(
    s,
    user='user_dn',
    password='user_password',
    auto_bind='NONE',
    version=3,
    authentication='SIMPLE',
    client_strategy='SYNC',
    auto_referrals=True,
    check_names=True,
    read_only=False,
    lazy=False,
    raise_exceptions=False
    )

```

Обратитесь к [[Server]] и [[Connection|connection]] документации для информации о стандартных параметрах.

## Anonymous Bind

Anonymous Bind  выполняет Simple Bind с именем пользователе и паролем указанным как пустая строка. Библиотека [[ldap3]] имеет  определенные опции для этого: 

``` python

# Импорт классов и констант
from ldap3 import Server, Connection, ALL

# Определение объекта сервера
s = Server(
    'servername',
    # Определение не безопасного LDAP сервера, запрос информации о DSE и схеме
    get_info=ALL
    ) 

# Определение объекта подключения
c = Connection(s)  # Определение ANONYMOUS подключения

# Выполнение операции Bind
if not c.bind():
    print('error in bind', c.result)

```

Объекты [[Server]] и [[Connection|connection]] созданы с использованием стандартных параметров:

``` python

s = Server(
    host='servername',
    port=389,
    use_ssl=False,
    get_info='ALL'
    )
c = Connection(
    s,
    auto_bind='NONE',
    version=3,
    authentication='ANONYMOUS',
    client_strategy='SYNC',
    auto_referrals=True,
    check_names=True,
    read_only=False,
    lazy=False, 
    raise_exceptions=False
    )

```

Для использования базовой SSL аутентификации измените определение сервера на:


``` python

s = Server(
    'servername',
    use_ssl=True,
    get_info=ALL
    )  # определяет безопасный LDAP сервер на стандартном порту 636

```

## StartTLS

Если вы хотите поднять безопасный транспортный уровень для зашифрованной сессии, вы можете выполнить расширенную операцию  StartTLS. С этим механизмом вы можете  обернуть простой сокет в SSL зашифрованный сокет: 

``` python

с.start_tls()

```

Коммуникации на транспортном уровне шифруются. Вы должны должным образом настроить объект [[Server]] добавив TLS объект с соответствующей конфигурацией:

``` python

t = Tls(
    local_private_key_file='client_private_key.pem',
    local_certificate_file='client_cert.pem',
    validate=ssl.CERT_REQUIRED,
    version=ssl.PROTOCOL_TLSv1,
    ca_certs_file='ca_certs.b64'
    )
s = Server(
    'servername',
    tls=t,
    get_info=ALL
    )

```

Пожалуйста обратитесь к SSL and TLS секции для большей информации.

## SASL

Три SASL механизма сейчас реализованы в библиотеке [[ldap3]]: EXTERNAL, DIGEST-MD5, GSSAPI (Kerberos, через пакет gssapi) и PLAIN. 'DIGEST-MD5' реализован хоть и  **устарел**, и оставлен в истории (RFC6331, July 2011) из-за того, что он **ненадежный и неподходящий для использования в протоколах** (как указано RFC)

Для запроса доступного на сервере SASL механизма, вы должны прочитать информацию опубликованную сервером. Библиотека [[ldap3]] имеет удобный путь для реализации этого:

``` python

from ldap3 import Server, Connection, ALL
s = Server(
    'servername',
    # define an unsecure LDAP server, requesting info on DSE and schema
    get_info=ALL
    )  
c = Connection(s)
# establish connection without performing any bind (equivalent to ANONYMOUS bind)
c.open()  
print(s.info.supported_sasl_mechanisms)

```

Получите на выход список SASL механизмов поддерживаемых сервером:

``` python 

['EXTERNAL', 'DIGEST-MD5', 'GSSAPI']

```

### External

Вы можете использовать механизм EXTERNAL, когда вы находить на защищенном (TLS) канале. Вы можете предоставить строку идентификатора авторизации в `sasl_credentials` или позволить серверу довериться предоставленным учетным данным при создании защищенного канала


``` python

from ldap3 import Server, Connection, Tls, SASL,EXTERNAL

tls = Tls(
    local_private_key_file = 'key.pem',
    local_certificate_file = 'cert.pem',
    validate = ssl.CERT_REQUIRED,
    version = ssl.PROTOCOL_TLSv1,
    ca_certs_file = 'cacert.b64'
    )
server = Server(
    host = test_server,
    port = test_port_ssl,
    use_ssl = True,
    tls = tls
    )
c = Connection(
    server,
    auto_bind = True,
    version = 3,
    client_strategy = test_strategy,
    authentication = SASL,
    sasl_mechanism = EXTERNAL,
    sasl_credentials = 'username'
    )

```

### Digest-MD5

Для использования механизма Digest-Md5 вы должны передать кортеж из 4 или 5 значений как ``sasl_credentials: realm, user, password, authz_id, enable_singing. Вы можете передать `None` для 'realm', 'authz_id' и 'enable_signing' если не используете:

``` python

from ldap3 import Server, Connection, SASL, DIGEST_MD5

server = Server(
    host = test_server,
    port = test_port
    )
c = Connection(
    server,
    auto_bind = True,
    version = 3,
    client_strategy = test_strategy,
    authentication = SASL,
    sasl_mechanism = DIGEST_MD5,
    sasl_credentials = (
        None,
        'username',
        'password',
        None,
        'sign'
        )
    )

```

Имя пользователя (Username) не обязательно должно быть записью LDAP, но оно может быть любым распознаваемым сервером идентификатором (например почта, имя участника и т.д).
Если вы передаете `None` в качестве 'realm', то будет использован стандартный realm LDAP сервера. 

`enable_signing` - не обязательный аргумент, который подходит только для Digest-MD5 аутентификации. Этот аргумент включает или выключает подпись (Защита целостности) при выполнении LDAP запросов. Подпись LDAP это способ предотвратить повторные атаки без шифрования LDAP трафика. Microsoft публично рекомендует принудительно использовать LDAP подпись при общении с Active Directory сервером:

https://support.microsoft.com/en-us/help/4520412/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows

- При `enable_signing` установленном на `sign`, Запросы LDAP подписываются и подпись LDAP ответа проверяется.
- При `enable_signing` установленном как любое другое значение или не установлено, LDAP запросы не подписываются.

Также, DIGEST-MD5 аутентификация с шифрованием в дополнение к защите целостности (`qop=auth-conf`) не поддерживается [[ldap3]].

**Использование DIGEST-MD5 без подписи LDAP считается устаревшим и не должно использоваться.**

### Kerberos

^23e93b

Аутентификация Kerberos использует пакет `gssapi`. Вы должны установить его и настроить ваше окружение Kerberos для использования механизма GSSAPI:

``` python

from ldap3 import Server, Connection, Tls, SASL, KERBEROS
import ssl

tls = Tls(
    validate=ssl.CERT_NONE,
    version=ssl.PROTOCOL_TLSv1_2
    )
server = Server(
    '<servername>',
    use_ssl=True,
    tls=tls
    )
c = Connection(
    server,
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )
c.bind()
print(c.extend.standard.who_am_i())

```

Вы можете указать какой главный Kerberos клиент будет использован указав параметр `user` когда объявляете объект [[Connection|connection]]:

``` python
c = Connection(
    server,
    user='ldap-client/client.example.com',
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )

```

По умолчанию библиотека пытается выполнить привязку к субъект-службы для домена, к которому вы пытались подключиться. Если ваш целевой сервис LDAP использует round-robin DNS, вполне вероятно, что hostname подключения не будет совпадать. В этом случае, вы можете или явно указать hostname как первый элемент параметров подключения `sasl_credentials` или передать соответствующее значение перечисления `ReverseDnsSetting` как первый элемент, что бы выполнить обратный поиск DNS:

``` python

# Переопределение hostname сервера для аутентификации
c = Connection(
    server,
    sasl_credentials=(
        'ldap-3.example.com',
        ),
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )

# Выполнение обратного DNS поиска чтобы определить hostname для аутентификации несмотря на спецификацию сервера
c = Connection(
    server,
    sasl_credentials=(
        ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,
        ),
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )

# Только выполнение обратного DNS поиска чтобы определить hostname для аутентификации, если хост сервера указан как IP адрес
c = Connection(
    server,
    sasl_credentials=(
        ReverseDnsSetting.REQUIRE_RESOLVE_IP_ADDRESSES_ONLY,
        ),
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )

# Выполнение обратного DNS поиска чтобы определить hostname для аутентификации, но если поиск завершится неудачей, продолжите и попробуйте использовать host сервера как есть.
# Это полезно когда работает с пулами серверов, где некоторые сервера резолвятся через обратный DSN и нуждаются в этом, а другие сервера не резолвятся и не нуджаются в этом
c = Connection(
    server,
    sasl_credentials=(
        ReverseDnsSetting.OPTIONAL_RESOLVE_ALL_ADDRESSES,
        ),
    authentication=SASL,
    sasl_mechanism=KERBEROS
    )

```

> [!NOTE]
> ### Заметка
> [[ldap3]] на текущий момент не поддерживает любые уровни безопасности данных SASL, только аутентификацию..
>
> Если ваш сервер требует строку Security Strenght Factor (SSF), вы можете получать ошибку `LDAPStrongerAuthRequiredReduls` при binding, например:
>
> SASL:[GSSAPI]: Sing or Seal are required

### Plain

SASL механизм PLAIN отправляет данные в чистом тексте, так он должен полагаться на другие значения безопасности подключения между клиентом и LDAP сервером. Как указано в RFC4616 механизм PLAIN не должен использоваться без адекватной защиты безопасности данных, так как этот механизм не предоставляет защиту целостности или конфиденциальности. Механизм намеревался для использования с защитой безопасности данных предоставленной протоколом уровня приложения, обычно через использованием им Transport Layer Security (TLS) сервис.

Для использование PLAIN механизма вы должны передать кортеж из 3 значений как `sasl_credentioal`: authorization_id, authentification_id, password). Вы можете отправить None для authorization_id если не используете. 

``` python

from ldap3 import Server, Connection, SASL, PLAIN

server = Server(
    host = test_server,
    port = test_port,
    use_ssl=True
    )
c = Connection(
    server,
    auto_bind=True,
    authentication=SASL,
    sasl_mechanism=PLAIN,
    sasl_credentials=(
        None,
        'username',
        'password'
        )
    )

```


## NTLM

^74f22c

Библиотека [[ldap3]] поддерживает дополнительный метод для связки с сервисом Active Directory через метод NTLM:

``` python

# Импорт классов и констант
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM

# Определение объектов сервера и подключения
s = Server('servername', get_info=ALL)
c = Connection(s, user="AUTHTEST\\Administrator", password="password", authentication=NTLM)
# выполнение операции Bind
if not c.bind():
    print('error in bind', c.result)

``` 

Этот аутентификационный метод специфичен для Active Directory и использует собственный протокол аутентификации именованный SICILY который нарушает LDAP RFC но может быть использован для доступа к AD.

Когда связываем через NTLM, он так же позволяет аутентифицироваться с LM:NTLM хешем вместо пароля:

``` python

c = Connection(
    s,
    user="AUTHTEST\\Administrator",
    password="E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C",
    authentication=NTLM)

```

## LDAPI (LDAP over IPC)

Если ваш LDAP сервер предоставляет UNIX сокет подключение, вы можете использовать **ldapi:** (Межпроцессорное взаимодействие) схему для доступа к нему с той же машины:

``` python

>>> # досту4п OpenLDAP серверу в сессии пользователя root 
>>> s = Server('ldapi:///var/run/slapd/ldapi')
>>> c = Connection(s, authentication=SASL, sasl_mechanism=EXTERNAL, sasl_credentials='')
>>> c.bind()
True
>>> c.extend.standard.who_am_i()
dn:cn=config

```

Использование механизма SASL EXTERNAL позволяет вам предоставить серверу учетные данные вошедшего пользователя.

При доступе к вашему LDAP через UNIX сокет вы можете выполнить любую обычную LDAP операцию. Это должно быть быстрее чем использовать TCP подключение. Вам не нужно использовать SSL при подключении через сокет, потому что все взаимодействия в памяти сервера и не передаются по проводам.


## Bind как другой юзер при открытом [[Connection]]

Протокол LDAP позволяет bind от другого пользователя при открытом подключении. В этом случае вы можете использовать метод `rebind()`, который позволяет вам изменить пользователя и метод аутентификации пока подключение открыто:

``` pyhton

# импорт классов и контстант
from ldap3 import Server, Connection, ALL, LDAPBindError

# определение сервера
s = Server(
    'servername',
    # определение не безопасного LDAP сервера, запрашивающего информацию по DSE и схеме
    get_info=ALL
    )  
# определение подключения
c = Connection(s, user='user_dn', password='user_password')

# выполнение bind
if not c.bind():
    print('error in bind', c.result)

# Снова bind с другим пользователем
if not c.rebind(user='different_user_dn', password='different_user_password')
    print('error in rebind', c.result)

```

Если учетные данные неверны или сервер не позволяет тебе `rebind`, сервер может внезапно закрыть подключение. Это состояние проверяется методом `rebind()` и исключение LDAPBindError будет выдано при перехвате.

Если вы хотите выдать исключение, когда учетные данные не верны, вы можете использовать параметр `raise_exceptopn=True` в определении [[Connection|connection]]. Держите в голове, что сетевые ошибки всегда возвращают исключение, даже если `rase_exceptions` установлено как `False`

## Расширенное логирование

Для получения представление о том, что происходит когда вы выполняете Simple Bind операцию используя StartTls функцию безопасности, это расширенный лог из сессии к OpenLdap серверу из Windows клиента с двойным стеком IP:

``` log

# Инициализация:

INFO:ldap3:ldap3 library initialized - logging emitted with loglevel set to DEBUG - available detail levels are: OFF, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED
DEBUG:ldap3:ERROR:detail level set to EXTENDED
DEBUG:ldap3:BASIC:instantiated Server: <Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO')>
DEBUG:ldap3:BASIC:instantiated Usage object
DEBUG:ldap3:BASIC:instantiated <SyncStrategy>: <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - No strategy - async - real DSA - not pooled - cannot stream output>
DEBUG:ldap3:BASIC:instantiated Connection: <Connection(server=Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO'), user='cn=admin,o=test', password='<stripped 8 characters of sensitive data>', auto_bind='NONE', version=3, authentication='SIMPLE', client_strategy='SYNC', auto_referrals=True, check_names=True, collect_usage=True, read_only=False, lazy=False, raise_exceptions=False)>
DEBUG:ldap3:NETWORK:opening connection for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:reset usage metrics
DEBUG:ldap3:BASIC:start collecting usage metrics
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]>
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]>
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]> with mode IP_V6_PREFERRED
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]> with mode IP_V6_PREFERRED


# Открытие подключения (подпытка IPv6 после IPv4):

DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]
DEBUG:ldap3:ERROR:<socket connection error: [WinError 10061] No connection could be made because the target machine actively refused it.> for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <local: [::]:49610 - remote: [None]:None> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]
DEBUG:ldap3:NETWORK:connection open for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:start START TLS operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:instantiated Tls: <Tls(validate=0)>


# запуск TLS - обертка сокета в ssl сокет:

DEBUG:ldap3:BASIC:starting tls for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:start EXTENDED operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:EXTENDED request <{'name': '1.3.6.1.4.1.1466.20037', 'value': None}> sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <1> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=1
>> protocolOp=ProtocolOp:
>>  extendedReq=ExtendedRequest:
>>   requestName=b'1.3.6.1.4.1.1466.20037'
DEBUG:ldap3:NETWORK:sent 31 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 14 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 1 ldap messages via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
<<LDAPMessage:
<< messageID=1
<< protocolOp=ProtocolOp:
<<  extendedResp=ExtendedResponse:
<<   resultCode='success'
<<   matchedDN=b''
<<   diagnosticMessage=b''
DEBUG:ldap3:PROTOCOL:EXTENDED response <[{'referrals': None, 'dn': '', 'type': 'extendedResp', 'result': 0, 'description': 'success', 'responseName': None, 'responseValue': b'', 'message': ''}]> received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:done EXTENDED operation, result <True>
DEBUG:ldap3:BASIC:tls started for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:socket wrapped with SSL using SSLContext for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: [None]:None - remote: [None]:None> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:done START TLS operation, result <True>


# Выполнение Bind операции Simple Bind методом:

DEBUG:ldap3:BASIC:start BIND operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:performing simple BIND for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:simple BIND request <{'name': 'cn=admin,o=test', 'authentication': {'sasl': None, 'simple': '<stripped 8 characters of sensitive data>'}, 'version': 3}> sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <2> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=2
>> protocolOp=ProtocolOp:
>>  bindRequest=BindRequest:
>>   version=3
>>   name=b'cn=admin,o=test'
>>   authentication=AuthenticationChoice:
>>    simple=b'<stripped 8 characters of sensitive data>'
DEBUG:ldap3:NETWORK:sent 37 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 14 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 1 ldap messages via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>:
<<LDAPMessage:
<< messageID=2
<< protocolOp=ProtocolOp:
<<  bindResponse=BindResponse:
<<   resultCode='success'
<<   matchedDN=b''
<<   diagnosticMessage=b''
DEBUG:ldap3:PROTOCOL:BIND response <{'referrals': None, 'dn': '', 'type': 'bindResponse', 'result': 0, 'description': 'success', 'saslCreds': None, 'message': ''}> received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:49611 - remote: 192.168.137.104:389> - tls started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:done BIND operation, result <True>

```

Это используемые метрики данной сесии:

``` info

Connection Usage:
 Time: [elapsed:        0:00:01.908938]
   Initial start time:  2015-06-02T09:37:49.451263
   Open socket time:    2015-06-02T09:37:49.451263
   Close socket time:
 Server:
   Servers from pool:   0
   Sockets open:        1
   Sockets closed:      0
   Sockets wrapped:     1
 Bytes:                 96
   Transmitted:         68
   Received:            28
 Messages:              4
   Transmitted:         2
   Received:            2
 Operations:            2
   Abandon:             0
   Bind:                1
   Add:                 0
   Compare:             0
   Delete:              0
   Extended:            1
   Modify:              0
   ModifyDn:            0
   Search:              0
   Unbind:              0
 Referrals:
   Received:            0
   Followed:            0
 Restartable tries:     0
   Failed restarts:     0
   Successful restarts: 0

```

Как вы можете видеть, было две операции, одна для bind и одна для startTls (расширенная операция). Один сокет был открыт и был обернут в SSL. Все коммуникационные потоки получили 97 байт в 4 LDAP сообщениях.
