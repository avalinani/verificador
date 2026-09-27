# PDF Inspector & Signature Verifier

> Trabajo Fin de Máster · Servicio web para la auditoría técnica y forense de documentos PDF.
>
> **Estado:** en desarrollo. Este README es un documento vivo: se actualiza con cada tarea completada.
> Las funcionalidades marcadas como ⏳ están planificadas pero aún no implementadas.

## Índice

1. [Descripción general](#1-descripción-general)
2. [Cómo funciona](#2-cómo-funciona)
3. [Stack tecnológico](#3-stack-tecnológico)
4. [Instalación y ejecución](#4-instalación-y-ejecución)
5. [Estructura del proyecto](#5-estructura-del-proyecto)
6. [Funcionalidades principales](#6-funcionalidades-principales)
7. [Tests y calidad](#7-tests-y-calidad)
8. [Usuario y contraseña de prueba](#8-usuario-y-contraseña-de-prueba)
9. [Presentación](#9-presentación)
10. [Decisiones técnicas](#10-decisiones-técnicas)
11. [Historial de cambios](#11-historial-de-cambios)
12. [Repositorio y licencia](#12-repositorio-y-licencia)

---

## 1. Descripción general

**PDF Inspector & Signature Verifier** es un servicio web monolítico modular que analiza un documento PDF en un único ciclo de procesamiento y devuelve un informe JSON estructurado con:

- **Integridad criptográfica de las firmas digitales** (PAdES / CMS-PKCS#7): si la firma es matemáticamente válida y si el documento ha sido modificado después de firmarse.
- **Sellos de tiempo** (RFC 3161) y **cadena de confianza X.509** del firmante.
- **Revocación** (OCSP / CRL) como comprobación opcional y acotada.
- **Conformidad PDF/A-1b** mediante el módulo oficial *preflight* de Apache PDFBox.
- **Propiedades físicas**: versión, número de páginas, rotación y dimensiones por página, cifrado y permisos.

El servicio no guarda los documentos analizados: es **sin estado** y sin base de datos.

## 2. Cómo funciona

### 2.1 Flujo de análisis (objetivo)

```
Cliente (UI o Swagger)
   │  POST /api/v1/pdf/analyze  (multipart, PDF ≤ 20 MB)          ⏳
   ▼
api ──► application: AnalyzePdfUseCase                           ✅
            │ orquesta los puertos del dominio (ver §2.9)
            ├─► HashCalculator            SHA-256 / SHA-512       ✅
            ├─► PdfDocumentReader         estructura, páginas, permisos, XMP  ✅
            ├─► SignatureVerifier         /ByteRange + CMS + RFC 3161       ✅
            ├─► CertificateChainValidator PKIX contra trust store            ✅
            ├─► RevocationChecker         OCSP/CRL (opcional, timeout 2 s)   ⏳ (NoOp por ahora, T10)
            └─► PdfaConformanceValidator  preflight PDF/A-1b                 ✅
   ◄── PdfAnalysisReport (JSON)
```

La capa `api` (controlador REST, DTOs, mapeo de errores) todavía no existe (⏳, T09); `AnalyzePdfUseCase` ya es real y está cubierto por tests de unidad, un test de integración con adaptadores reales y por las reglas de arquitectura de ArchUnit (§2.9, §2.10).

### 2.2 Cómo se detecta que un documento ha cambiado después de firmarse

`infrastructure/bouncycastle/BcSignatureVerifier` implementa el puerto `SignatureVerifier` sobre PDFBox 3 (para leer los diccionarios de firma) y Bouncy Castle 1.86 (para el CMS), sin dejar escapar ningún tipo de esas librerías fuera del adaptador. Recorre **cada** campo de firma (`PDDocument#getSignatureFields()`) y evalúa cada uno de forma **independiente**, con su propio nombre de campo.

Una firma PDF no firma el fichero entero, sino los bytes indicados en el array **`/ByteRange`** del diccionario de firma. Ese array tiene cuatro números `[a b c d]`: dos tramos de bytes firmados que dejan un hueco en medio donde va la propia firma (`/Contents`, un contenedor CMS en hexadecimal).

La verificación comprueba, en este orden:

1. **Estructura del `/ByteRange`**: además de lo que ya valida el propio dominio (`ByteRangeCoverage`: empieza en 0, tramos sin solaparse, dentro del fichero), el adaptador comprueba a nivel de bytes que el hueco entre tramos está delimitado por `<`/`>` y que su longitud coincide exactamente con el tamaño hexadecimal de `/Contents`. Esta segunda comprobación se corrigió en la ronda de endurecimiento posterior a T04 (T04b): la longitud "esperada" se obtenía llamando a `PDSignature#getContents(byte[])`, que a su vez calcula los límites del propio hueco a partir de esos mismos números de `/ByteRange` -- comparar el hueco contra una longitud derivada del propio hueco es una tautología que nunca puede fallar. Ahora se usa `PDSignature#getContents()` (sin argumentos), que PDFBox resuelve de forma independiente recorriendo su propia estructura de objetos (tabla xref → diccionario → `/Contents`), sin usar en ningún momento los números de `/ByteRange`; un `/ByteRange` que declare un hueco de tamaño distinto al que realmente ocupa `/Contents` ahora se detecta. Un `/ByteRange` hostil o inconsistente (por ejemplo, una longitud negativa, que se sale del fichero, o que no coincide con `/Contents`) **nunca lanza una excepción**: se captura y esa firma se informa como `INVALID_SIGNATURE`, sin abortar el análisis de las demás firmas del documento.
2. **Integridad matemática (CMS)**: se lee `/Contents` con un único objeto ASN.1 (ver detalle técnico más abajo) y se verifica con Bouncy Castle (`SignerInformation#verify(...)`), que comprueba a la vez que el `messageDigest` firmado coincide con el resumen de los bytes cubiertos por `/ByteRange` y que la firma es válida para el certificado del firmante. Si un solo byte firmado cambia, la verificación falla (**`INVALID_SIGNATURE`**).
3. **Cobertura del fichero**: si el final del segundo tramo (`c + d`) alcanza el tamaño del fichero, la firma es **`INTACT`**. Si es menor, hay bytes añadidos **después** de firmar (una *actualización incremental*): la firma sigue siendo matemáticamente válida para su revisión, pero el resultado es **`MODIFIED_AFTER_SIGNING`**.

Con **varias firmas** (por ejemplo, un documento firmado dos veces) esto da un resultado que a primera vista sorprende pero es el comportamiento esperado de PDF: la **primera** firma queda como `MODIFIED_AFTER_SIGNING`, porque después de firmarse se le añadió una actualización incremental (la segunda firma); solo la **última** firma, cuyo `/ByteRange` alcanza el final real del fichero, es `INTACT`.

**Subfiltros soportados**: `adbe.pkcs7.detached` y `ETSI.CAdES.detached` se verifican por completo. `adbe.pkcs7.sha1`, `adbe.x509.rsa_sha1` y cualquier subfiltro desconocido se informan como **`UNSUPPORTED`** sin intentar verificarlos. `ETSI.RFC3161` (un sello de tiempo de *documento*, que no firma contenido sino que sella una revisión completa) se decidió mantener como `UNSUPPORTED`: verificarlo exigiría un camino de verificación distinto (interpretar el propio CMS como un `TimeStampToken` en lugar de como una firma CAdES normal, y un informe sin cadena de firmante en el sentido habitual), y el sello de **firma** (§2.6) cubre el caso que de verdad pide el TFM (demostrar cuándo se firmó una firma ya existente). Se documenta como decisión consciente, no como pendiente por omisión.

**Robustez frente a fallos parciales** (revisión posterior a T04, T04b): iterar los campos de firma de un documento hostil puede lanzar una excepción de tiempo de ejecución antes incluso de llegar al CMS (por ejemplo, al leer el nombre completo de un campo). Antes, esa excepción solo estaba protegida *dentro* de la evaluación del CMS/`ByteRange`, no en la lectura previa del campo; ahora todo el ciclo por campo (lectura + evaluación) está bajo la misma protección, así que un campo hostil nunca aborta el análisis de los demás. Además, si el CMS se verifica correctamente pero **no se puede volver a codificar** uno de los certificados extraídos a DER (un fallo de mapeo, no de criptografía), la firma ya no se informa como `INVALID_SIGNATURE`: se mantiene el `IntegrityStatus` real (calculado a partir del resultado criptográfico) con la cadena de certificados que sí se pudo mapear (parcial o vacía) y una nota de anomalía (`SignatureReport#anomaly`) explicando cuántos certificados no se pudieron mapear.

Estos casos (firma válida, byte manipulado, actualización incremental posterior, doble firma, `/ByteRange` hostil, subfiltro no soportado y campo de firma hostil) ya están demostrados con tests (ver [§7](#7-tests-y-calidad)).

### 2.6 Sellos de tiempo RFC 3161

Un sello de tiempo de **firma** (distinto del sello de tiempo de *documento* de §2.2) es un atributo CMS **no firmado** que una TSA (*Time-Stamping Authority*) añade a una firma ya existente: `id-aa-signatureTimeStampToken` (OID `1.2.840.113549.1.9.16.2.14`). Lo que sella no es el contenido del documento, sino **el valor de la propia firma** (los bytes de la firma RSA/DSA del firmante) — por eso puede añadirse *después* de firmar, sin invalidar la firma ni requerir volver a firmar nada.

**Por qué importa frente a la fecha de firma auto-declarada**: el diccionario de firma (`/M`) y el atributo CMS firmado `signingTime` son *auto-declarados* por el firmante — cualquiera con el certificado puede poner la fecha que quiera, sin ninguna garantía externa. Un sello de tiempo RFC 3161, en cambio, lo emite un tercero (la TSA) cuya propia firma puede verificarse: si el sello es válido, se tiene una prueba criptográficamente verificable de que la firma ya existía en ese instante, no solo la palabra del firmante. `TimestampInfo.genTime()` es esa fecha de la TSA; `claimedSigningTime` (en `SignatureReport`) sigue siendo la auto-declarada, y ambas conviven en el informe sin mezclarse.

**Verificación** (`infrastructure/bouncycastle/SignatureTimestampVerifier`), con Bouncy Castle `org.bouncycastle.tsp` (`TimeStampToken`), en dos partes independientes:

1. **Imprint del mensaje**: el sello declara un algoritmo de resumen y un valor (`messageImprint`). Se recalcula ese resumen —con el algoritmo que el propio sello declara, no uno fijo— sobre los bytes de la firma (`SignerInformation#getSignature()`) y se compara con el valor declarado. Si no coincide, el sello es inválido (`imprintValid=false`), pero **la integridad de la firma que lo contiene no se ve afectada**: son dos verificaciones independientes.
2. **Firma de la TSA**: el CMS del propio sello se verifica contra el certificado de la TSA embebido en él (`TimeStampToken#validate(...)`, construido con `JcaSimpleSignerInfoVerifierBuilder`), y se comprueba que ese certificado declara el uso extendido de clave `id-kp-timeStamping`; si no lo declara, no se rechaza la firma por eso, pero se añade una nota (`TimestampInfo#note`) — igual que con el atributo `signingCertificate`/`ESSCertID` del propio RFC 3161, que enlaza el sello a un certificado concreto y por tanto impide sustituirlo por otro sin invalidar la verificación.

**Casos límite, ninguno lanza una excepción**: sin sello → `TimestampInfo.absent()` (`genTime=null`). Sello con imprint incorrecto → `imprintValid=false`, pero la firma que lo contiene sigue `INTACT` si su propio CMS es válido. Sello con bytes ASN.1 corruptos o que no se puede parsear como `TimeStampToken` → se informa igualmente inválido (`genTime=null`, con una nota explicando el motivo), sin afectar a la integridad de la firma. **(T05b)** Si el sello se valida correctamente pero el certificado de la TSA no se puede volver a mapear a `CertificateInfo` (un fallo de codificación DER, no criptográfico — el mismo tipo de fallo ya tolerado para la cadena del firmante en §2.5), ya **no** se descarta todo el resultado del sello: `genTime`, `imprintValid` y `signatureValid` se conservan (son verificaciones independientes de si se pudo extraer el certificado) y solo se añade una nota indicando que los datos del certificado de la TSA no se pudieron mapear.

**Extensión mínima del dominio**: `TimestampInfo` ganó `signatureValid`, `tsaCertificate` (un `CertificateInfo`, reutilizando el tipo ya existente — el dominio sigue sin depender de ninguna librería de certificados) y `note`; `SignatureReport` ganó `anomaly` (ver más arriba) con el mismo propósito: informar una anomalía sin forzar al informe entero a un estado binario válido/inválido.

### 2.3 Modelo de dominio y puertos

El núcleo del sistema (`domain/`) es Java puro: no importa Spring, PDFBox ni Bouncy Castle (se comprueba en cada tarea). Todo el informe se modela con **records inmutables** que validan sus datos al construirse y copian las listas que reciben, para que nadie pueda modificarlas desde fuera.

| Concepto | Tipo | Regla que aplica |
|---|---|---|
| Informe completo | `PdfAnalysisReport` | Agrupa hashes, estructura, seguridad, PDF/A y firmas |
| Hashes | `DocumentHashes` | SHA-256 (64 hex) y SHA-512 (128 hex), en minúsculas |
| Página | `PageInfo`, `Box` | MediaBox/CropBox con ancho y alto calculados |
| Rotación | `Rotation` | Normaliza a 0/90/180/270 (`-90 → 270`, `450 → 90`); un valor que no sea múltiplo de 90 es inválido |
| Orientación | `Orientation` | Se calcula **después** de rotar: a 90° o 270° se intercambian ancho y alto |
| Cobertura de firma | `ByteRangeCoverage` | 4 valores, empieza en 0, tramos sin solaparse; indica si cubre todo el fichero |
| Estado de integridad | `IntegrityStatus` | `INTACT`, `MODIFIED_AFTER_SIGNING`, `INVALID_SIGNATURE`, `UNSUPPORTED` |
| Certificado | `CertificateInfo` | Sujeto, emisor, fechas, algoritmo, URLs OCSP/CRL y el certificado codificado (DER) |
| Sello de tiempo | `TimestampInfo` | `genTime`, `tsaName`, `imprintValid`, `signatureValid`, certificado de la TSA y una nota opcional; `absent()` cuando no hay sello |
| Cadena y revocación | `ChainStatus`, `RevocationStatus` | Empiezan como `NOT_CHECKED` y se completan más tarde; `ChainStatus` ya lo calcula `PkixCertificateChainValidator` (§2.7) |

Los **puertos** son interfaces pequeñas que la infraestructura implementará con las librerías: `HashCalculator`, `PdfDocumentReader`, `SignatureVerifier`, `CertificateChainValidator`, `RevocationChecker` y `PdfaConformanceValidator`.

El verificador de firmas devuelve cada `SignatureReport` con la cadena y la revocación sin comprobar. Después, el caso de uso las completa con `withChainAndRevocation(...)`. Así cada adaptador tiene una sola responsabilidad y la revocación puede omitirse sin tocar el verificador.

> **Detalle técnico**: PDFBox reserva un hueco fijo para `/Contents` y lo rellena con ceros. Al extraer la firma hay que leer un único objeto ASN.1 (`ASN1InputStream.readObject()`), porque el constructor directo de `CMSSignedData` de Bouncy Castle rechaza los bytes de relleno ("Extra data detected in stream").

### 2.4 Lectura de estructura, seguridad y declaración PDF/A

`infrastructure/pdfbox/PdfBoxDocumentReader` implementa el puerto `PdfDocumentReader` sobre PDFBox 3 y `xmpbox`, sin dejar escapar ningún tipo de esas librerías fuera del adaptador:

- **Versión**: la de cabecera se extrae directamente de los primeros bytes (`%PDF-x.y`, expresión regular); la del catálogo, con `PDDocumentCatalog#getVersion()` (puede ser `null` si el documento no la declara). Si no se encuentra la cabecera `%PDF-` en los primeros 1024 bytes pero PDFBox consigue igualmente parsear el fichero (algo que los lectores de PDF, incluido PDFBox, tratan con tolerancia), `headerVersion` se informa como `null` ("desconocida") en vez de abortar el análisis.
- **Rotación por página**: se lee el atributo raw `/Rotate` con `PDPageTree#getInheritableAttribute`, que además de heredar el valor desde un nodo `/Pages` superior (cuando la página no lo declara ella misma) devuelve el valor **sin normalizar**. Se prefiere a `PDPage#getRotation()` porque este último ya normaliza y hereda, pero cuando el valor no es múltiplo de 90 lo convierte silenciosamente en `0`, ocultando la anomalía. Solo un `COSInteger`, o un `COSFloat` sin parte decimal (p. ej. `90.0`), se considera válido; un real no entero (p. ej. `90.5`) o un valor no numérico se marca inválido **sin truncarlo silenciosamente** -truncar `90.5` a `90` haría parecer válido un valor que no lo es-. El raw pasa por `Rotation.tryFromDegrees(...)`: si es válido se usa para calcular la orientación; si no, `PageInfo` lo expone igualmente (`rawRotation`, `rotationValid()`, ambos consistentes con `rotation` por construcción) y la orientación se calcula como si fuera `0°`, sin abortar el análisis.
- **MediaBox / CropBox y orientación**: se leen con `PDPage#getMediaBox()`/`getCropBox()` (esta última ya hereda de la MediaBox si no está declarada) y se calcula la orientación después de aplicar la rotación efectiva.
- **Número de revisiones**: `infrastructure/pdfbox/RevisionCounter` recorre la cadena de referencias cruzadas (`xref`/`trailer`) siguiendo los enlaces `/Prev` desde el último `startxref` hacia atrás, contando una revisión por cada sección de xref visitada, en vez de contar apariciones del marcador `%%EOF`. Ese conteo por marcador sobrestima los PDF *linealizados* (los que llevan una sección de xref adicional al principio del fichero para "vista web rápida" de Adobe): esa sección adicional está encadenada por `/Prev` igual que una actualización incremental real, pero es la **misma** revisión lógica, no una nueva. `RevisionCounter` detecta esta situación buscando la marca `/Linearized` cerca del principio del fichero y, si la encuentra, no cuenta esa sección de xref como una revisión aparte. PDFBox no genera ficheros linealizados al guardar, así que este caso se prueba con una estructura de bytes construida a mano en el test (dos secciones de xref con `/Prev`, la primera precedida por un diccionario mínimo de linealización), no con un fixture real. Sigue siendo una heurística a nivel de bytes -un fichero deliberadamente hostil podría falsear los enlaces `/Prev`- con una salvaguarda contra bucles infinitos (un conjunto de posiciones ya visitadas detiene el recorrido en cuanto una vuelve a aparecer, en vez de repetirla) y una vuelta al conteo por `%%EOF` si no se encuentra ninguna cadena de xref o si el `startxref` declarado cae fuera del fichero.
  - **Rendimiento** (revisión posterior a T04, T04b): la implementación original volvía a recorrer el fichero completo, desde el principio de cada sección hasta el final, en **cada** salto de la cadena `/Prev` -- coste cuadrático en ficheros con muchas revisiones (varios segundos en un fichero sintético de ~5 MB con 2000 revisiones). Ahora localiza de una sola pasada, por cada palabra clave relevante (`stream`, `startxref`, `/Prev`), todas sus apariciones ordenadas, y cada salto de la cadena las busca con una búsqueda binaria en vez de volver a recorrer el fichero: coste total `O(n log n)` en vez de `O(saltos × n)`, verificado con el mismo fichero sintético de 2000 revisiones (por debajo de 3 segundos, frente a los ~9,6 s de la versión anterior).
- **Cifrado y permisos**: `PDDocument#isEncrypted()` más `AccessPermission`, mapeado a los ocho valores de `Permission`. Un documento sin contraseña de usuario (o con contraseña de usuario vacía) se abre y se informan sus restricciones reales; uno con contraseña de usuario no vacía no puede abrirse y lanza `EncryptedPdfException`.
- **Declaración PDF/A (XMP)**: se exportan los metadatos XMP del catálogo (`PDMetadata`) y se parsean con `DomXmpParser` (del artefacto `xmpbox`, dependencia transitiva de `preflight`, ya en el classpath), extrayendo `pdfaid:part`/`pdfaid:conformance` del esquema `PDFAIdentificationSchema`. Sin metadatos XMP, o sin ese esquema, o con XMP corrupto, se informa `PdfaDeclaration.NONE` en lugar de fallar todo el análisis. Esto es solo la *declaración*; la validación formal PDF/A-1b con *preflight* llega en una tarea posterior.
- Cualquier fichero que PDFBox no pueda parsear (corrupto o que no sea un PDF) lanza `InvalidPdfException`, envolviendo la `IOException` original.

`infrastructure/crypto/JcaHashCalculator` implementa `HashCalculator` con `java.security.MessageDigest` (SHA-256/SHA-512) y `HexFormat`, sin depender de PDFBox ni Bouncy Castle.

### 2.5 Extracción de certificados

Para cada firma con una verificación CMS válida, `BcSignatureVerifier` extrae del propio CMS el certificado del firmante y todos los certificados incluidos (normalmente firmante + emisor), y los mapea a `CertificateInfo` (sujeto y emisor en formato X.500, número de serie en hexadecimal, fechas de validez, algoritmo de firma, certificado codificado en DER). La cadena se ordena **firmante primero**, siguiendo el emisor de cada certificado hasta llegar a uno autofirmado (la raíz) o hasta que no se encuentre el siguiente emisor dentro del propio CMS.

De cada certificado se leen además las URLs de sus extensiones **Authority Information Access** (OCSP) y **CRL Distribution Points**, si las declara. Una extensión ausente o mal formada no invalida el certificado: simplemente se informa sin URLs para esa extensión (**T05b**: probado también directamente para el propio mapeador, no solo de forma indirecta a través de un PDF real). La comprobación de revocación (`revocation`) queda, por ahora, como `notChecked()` — la completará el caso de uso en una tarea posterior (T10). La validación de la cadena contra un almacén de confianza (`chainStatus`) ya está implementada (§2.7); su integración en el caso de uso llega en T08.

### 2.7 Cadena de confianza X.509 (PKIX)

`infrastructure/pki/PkixCertificateChainValidator` implementa el puerto `CertificateChainValidator` con la implementación PKIX de la propia JDK (`java.security.cert.CertPathBuilder` + `PKIXBuilderParameters`), sin depender de Bouncy Castle para esta parte — el dominio (`CertificateChainValidator`, `ChainStatus`) sigue sin conocer ningún tipo de certificados.

- **Momento de validación**: `validate(chain, validationTime)` recibe el `Instant` contra el que se comprueban vigencia y confianza; **quién decide ese instante es el caso de uso** (T08), no este adaptador — será el sello de tiempo RFC 3161 si es válido, si no la fecha de firma auto-declarada, y si no hay ninguna, el instante actual.
- **Revocación deliberadamente desactivada aquí** (`setRevocationEnabled(false)`): comprobar OCSP/CRL es responsabilidad de T10, aplicada por separado una vez la cadena ya es de confianza.
- **Estados** (`ChainStatus`): `TRUSTED` (la ruta se construye y todos los certificados son de confianza), `UNTRUSTED_ROOT` (la cadena llega a un certificado autofirmado, pero no está en el almacén configurado), `INCOMPLETE_CHAIN` (falta un emisor: la cadena no llega a ningún certificado autofirmado), `EXPIRED` (algún certificado de la cadena presentada está fuera de su periodo de validez en `validationTime` — esta comprobación es previa e independiente de PKIX), `NOT_CHECKED` (lista vacía).
- **Cómo se distingue `UNTRUSTED_ROOT` de `INCOMPLETE_CHAIN`**: el `CertPathBuilder` de la JDK no siempre distingue estos dos motivos de fallo de forma estable entre versiones, así que ante un fallo de construcción de ruta se aplica una comprobación propia, independiente: ¿la cadena presentada es *estructuralmente completa* (cada certificado verifica criptográficamente contra la clave pública del siguiente, hasta llegar a uno autofirmado)? Si lo es, el problema es que esa raíz no es de confianza (`UNTRUSTED_ROOT`); si no llega a ninguna raíz autofirmada, falta un eslabón (`INCOMPLETE_CHAIN`).
- **Almacén de confianza** (`TrustAnchorProvider`): combina, de forma aditiva, (a) las raíces españolas empaquetadas en `src/main/resources/truststore/` (classpath), y (b) opcionalmente un directorio externo de certificados y/o un fichero PKCS#12, ambos como parámetros del constructor por ahora (la configuración por propiedades de Spring llega en T09).
- **Sin lista de confianza europea (TSL/EU LOTL)**: la cadena se valida contra el almacén propio de raíces españolas descrito abajo, no contra la lista de confianza de la UE — decisión ya reflejada en [§10](#10-decisiones-técnicas).

**Raíces españolas empaquetadas** (`src/main/resources/truststore/`, con procedencia completa y huellas SHA-256 en `truststore/SOURCES.md`):

| Fichero | Autoridad | Válida hasta |
|---|---|---|
| `ac-raiz-fnmt-rcm.pem` | AC RAIZ FNMT-RCM | 2030-01-01 |
| `ac-raiz-fnmt-rcm-servidores-seguros.pem` | AC RAIZ FNMT-RCM SERVIDORES SEGUROS | 2043-12-20 |
| `accvraiz1.pem` | ACCVRAIZ1 (Agencia de Tecnología y Certificación Electrónica, GVA) | 2030-12-31 |
| `firmaprofesional-ac-raiz.pem` | Autoridad de Certificacion Firmaprofesional CIF A62634068 | 2036-05-05 |
| `izenpe-com.pem` | Izenpe.com | 2037-12-13 |
| `ac-raiz-dnie-2.pem` | AC RAIZ DNIE 2 (Dirección General de la Policía) | 2043-09-27 |

Cada raíz se descargó por HTTPS directamente de la web oficial de su propia autoridad y se incluye **solo** porque su huella SHA-256 se verificó de forma independiente (contra el informe oficial de CCADB y/o la Lista de Confianza española), nunca por la sola descarga; `truststore/SOURCES.md` documenta cada fuente de descarga y de verificación. Ninguna raíz se incluye sin esa verificación independiente.

**Cómo añadir raíces propias**: sin tocar el código, pasando un directorio externo (un certificado por fichero, PEM o DER) y/o un fichero PKCS#12 al construir `TrustAnchorProvider` — se combinan con las raíces empaquetadas, nunca las sustituyen.

**Endurecimiento (T06b, revisión posterior a T06)**:

- `RevisionCounter` guardaba su contador de pasos de escaneo (diagnóstico solo para tests) en un campo `static` — inofensivo con un test en un solo hilo, pero una condición de carrera real en cuanto el servicio atienda peticiones concurrentes (un `reset` de una llamada podía pisar el conteo de otra en curso). Se sustituyó por una instancia local (`ScanStats`) creada en cada llamada y pasada como parámetro por todo el recorrido: no queda ningún estado compartido mutable. Probado con 16 hilos ejecutando `count(...)` concurrentemente sobre distintos documentos, comprobando que cada uno obtiene exactamente el conteo que le corresponde.
- `PkixCertificateChainValidator`: un certificado que no se podía volver a parsear desde su codificación DER (bytes hostiles o corruptos) lanzaba una `IllegalStateException` sin capturar. Ahora se informa como `INCOMPLETE_CHAIN` (un certificado que ni siquiera se puede parsear no aporta ningún enlace verificable a la cadena) en vez de abortar el análisis; el fallo concreto se registra por log para diagnóstico.
- `TrustAnchorProvider`: el directorio externo y el fichero PKCS#12 ya tienen tests propios (directorio temporal con certificados PEM/DER válidos y un fichero inválido; PKCS#12 real generado en el propio test). Un fichero no válido dentro del directorio externo ya no aborta la carga completa del almacén: se omite (y se registra por log), igual que el resto de adaptadores del proyecto ante una entrada hostil aislada.
- `TrustAnchorProviderTest`: la comprobación "las raíces no han caducado" comparaba contra `Instant.now()` — una bomba de tiempo, porque la raíz que antes caduca (FNMT-RCM, 2030-01-01) empezaría a fallar el test años antes de que el certificado necesite reemplazarse de verdad. Ahora compara contra una fecha de referencia fija (2026-09-27).

### 2.8 Validación formal PDF/A-1b (*preflight*)

`infrastructure/preflight/PreflightPdfaValidator` implementa el puerto `PdfaConformanceValidator` con el módulo *preflight* de Apache PDFBox (`PreflightParser` + `PreflightDocument`), validando **siempre** contra el nivel PDF/A-1b, sin mirar la declaración XMP del propio documento para decidir si validar o no.

**Por qué solo PDF/A-1b**: *preflight* 3.0.8 no valida formalmente PDF/A-2 ni PDF/A-3 (solo 1a/1b). El puerto documenta este contrato explícitamente: un documento que declare PDF/A-2/3 en su XMP se valida igualmente contra las reglas 1b (que casi seguro no cumplirá, porque 2/3 permiten construcciones que 1b prohíbe) y el resultado se informa como `NON_COMPLIANT` con incidencias específicas de 1b — decidir que eso significa en realidad "solo se valida formalmente PDF/A-1b" en vez de "no es conforme" es responsabilidad del caso de uso (T08), que combina este resultado con `PdfDocumentReader#readPdfaDeclaration`, no de este adaptador.

**Qué comprueba PDF/A-1b** (a grandes rasgos, verificado empíricamente contra los fixtures de este proyecto): fuentes embebidas (un documento con texto en una fuente estándar no embebida, como Helvetica, incumple), un `OutputIntent` con perfil de color declarado para cualquier operador de color, sin flujos de referencias cruzadas comprimidos (`/XRef` de tipo *stream*, introducidos en PDF 1.5 — PDF/A-1 se basa en PDF 1.4), metadatos XMP presentes y coherentes, sin cifrado, entre otras reglas del propio *preflight*.

**Nunca lanza excepción por un documento individual, con una única excepción deliberada**: solo una entrada que ni siquiera declara una cabecera `%PDF-x.y` reconocible lanza la `InvalidPdfException` del dominio — más estrecho que `PdfBoxDocumentReader`, que lanza esa misma excepción para cualquier entrada que PDFBox no pueda parsear, incluida una truncada que sí declara cabecera. Un documento cifrado, uno con cabecera pero por lo demás roto, o un fallo interno del propio *preflight* se informan como `NOT_VALIDATED` con una incidencia explicativa, nunca se lanzan — un veredicto de conformidad ("no se puede validar") sigue siendo útil para el resto del análisis aunque el documento esté más roto de lo que PDFBox puro puede abrir.

**Diseño: una comprobación previa antes del *parseo* real de *preflight***: antes de invocar *preflight*, el documento se carga una vez con PDFBox normal (`Loader#loadPDF`) solo para distinguir cifrado de "cabecera presente pero roto". Esto supone un segundo *parseo* completo además del que hace el propio *preflight* — una preocupación de rendimiento real, aunque modesta, para un módulo ya de por sí pesado; sin medir todavía (perfilado de memoria/rendimiento es tarea de T12), pero queda anotado aquí.

**Incidencias**: cada resultado no conforme trae una lista de `PdfaIssue` (código + mensaje) deduplicada (mismo código y mensaje se cuentan una sola vez) y acotada a 200 elementos (con una incidencia `TRUNCATED` indicando cuántas se omitieron), para que un documento con un problema sistémico no produzca miles de incidencias casi idénticas.

**Fixture conforme** (`TestPdfFactory#pdfA1bCompliant`): el documento más pequeño que este proyecto pudo construir y que *preflight* valida como conforme es una página en blanco (sin texto, así que no hace falta embeber ninguna fuente — evita por completo la cuestión de licencias de fuentes) con un `OutputIntent` sRGB y XMP `pdfaid` (parte 1, conformidad B). Se probó también con `TestPdfFactory#unsigned()` (sin `OutputIntent` ni XMP) para el caso `NON_COMPLIANT`, con códigos de error reales de *preflight* capturados empíricamente (`3.1.3` fuente no embebida, `2.4.3` operador de color sin perfil, `7.1` sin metadatos PDF/A).

**(T07b)** El `OutputIntent` sRGB de ese fixture usaba originalmente el perfil ICC del propio Windows (`C:\Windows\System32\spool\drivers\color\sRGB Color Space Profile.icm`, leído solo en tiempo de test), lo que dejaba el test de la ruta `COMPLIANT` saltado (no fallado, pero tampoco probado) en el runner de CI, que es Linux. Ahora usa el perfil sRGB que trae el propio JDK (`java.awt.color.ICC_Profile.getInstance(ColorSpace.CS_sRGB).getData()`): comprobado empíricamente que *preflight* lo acepta igual como fuente válida de `OutputIntent`, sin necesidad de entorno gráfico (la implementación es Little CMS, no un servicio de color del sistema operativo), así que el test ya no se salta en ninguna plataforma.

**(T07b) Endurecimiento adicional**: la comprobación previa de cifrado/documento roto (antes de invocar *preflight*) ahora también captura una `RuntimeException` inesperada, no solo `IOException`/`InvalidPasswordException`, informando `NOT_VALIDATED` en vez de dejarla escapar. `PreflightPdfaValidatorTest` añadió cobertura directa de la rama `probe.isEncrypted()` (documento cifrado con contraseña de usuario vacía, distinta de la rama de excepción ya cubierta) y de la truncación/deduplicación de incidencias a 200 (probada llamando directamente al mapeador de errores, package-private, con una lista sintética de 250 incidencias — construir un documento real con más de 200 errores distintos de *preflight* no era práctico).

### 2.9 Orquestación: `AnalyzePdfUseCase` (T08)

`application/AnalyzePdfUseCase` es una clase de Java puro (sin Spring todavía; el cableado llega en T09) que orquesta, en un único método `analyze(fileName, content, options)`, todos los puertos del dominio descritos arriba, en este orden: hashes → estructura/seguridad/declaración PDF/A → validación formal PDF/A-1b (combinada con la declaración, ver más abajo) → firmas (cada una enriquecida con cadena de confianza y, opcionalmente, revocación). Recibe también un `java.time.Clock` inyectado (nunca `Instant.now()` directamente), para que `analyzedAt` y el "ahora" usado como último recurso de `validationTime` sean deterministas en los tests.

**Cómo se decide `validationTime` para la cadena de confianza** (§2.7): para cada firma, por este orden de preferencia — (1) el `genTime` del sello de tiempo RFC 3161 de la firma, solo si ese sello es válido (`imprintValid` y `signatureValid` ambos `true`); (2) si no, la fecha de firma auto-declarada (`claimedSigningTime`); (3) si tampoco hay, el instante actual del `Clock` inyectado. Esto es exactamente lo que ya documentaba `PkixCertificateChainValidator`, ahora implementado por quien realmente puede decidirlo (el caso de uso, no el adaptador).

**Combinación de la validación PDF/A** (contrato de §2.8): el caso de uso lee la declaración XMP `pdfaid` con `PdfDocumentReader#readPdfaDeclaration` y, por separado, el resultado formal 1b con `PdfaConformanceValidator#validate`. Si el documento declara PDF/A-2 o PDF/A-3 (`part != 1`), el informe final es `NOT_VALIDATED` con una incidencia `PDFA_PART_NOT_SUPPORTED` explicando que solo se valida formalmente PDF/A-1b — en vez del resultado formal 1b (casi con toda seguridad `NON_COMPLIANT`, con incidencias que no dicen nada real sobre la conformidad 2/3 del documento). Si declara PDF/A-1 o no declara ningún PDF/A, se usa el resultado formal tal cual.

**Revocación** (§10, opcional): si `AnalysisOptions.checkRevocation()` es `false`, cada firma recibe `RevocationStatus.notChecked()` sin llamar a ningún `RevocationChecker` (ni siquiera si la firma no tiene cadena de certificados). Si es `true`, se llama al `RevocationChecker` inyectado con el certificado del firmante (primer elemento de la cadena) y su emisor inmediato (segundo elemento, o `null` si la cadena solo tiene un certificado) — salvo que la cadena esté vacía, en cuyo caso tampoco hay nada que comprobar. La implementación real (OCSP/CRL) llega en T10; mientras tanto, `application/NoOpRevocationChecker` informa siempre `RevocationState.NOT_CHECKED` con el detalle `"revocation checking not available yet"` — deliberadamente distinto de `notChecked()` (que no lleva detalle), para que "se pidió pero aún no está implementado" se pueda distinguir de "no se pidió" si ese detalle llega a exponerse.

**Documento cifrado o corrupto: se propaga, no se atrapa**: `readStructure`/`readSecurity`/`readPdfaDeclaration` pueden lanzar `EncryptedPdfException` (contraseña de usuario no vacía) o `InvalidPdfException` (entrada corrupta o que no es un PDF). Ambas se propagan sin capturar fuera de `analyze(...)`: no existe un informe parcial razonable para un documento que ni siquiera se pudo abrir, y la futura capa REST (T09) debe mapear ambas a un `422`. Decisión documentada explícitamente en el Javadoc de la clase, no un descuido.

**Resiliencia: el fallo de una sección no debe perder el resto del informe**: dos adaptadores cuyo propio contrato ya dice que no deberían lanzar excepciones para un documento individual reciben, además, una guarda propia en el caso de uso (defensa en profundidad frente a un fallo inesperado del adaptador, no frente a su comportamiento documentado):

- `PdfaConformanceValidator#validate`: una `RuntimeException` inesperada se informa como `NOT_VALIDATED` con una incidencia explicativa, sin perder hashes/estructura/seguridad/firmas ya calculados.
- `SignatureVerifier#verify`: una `RuntimeException` inesperada se informa como "sin firmas" (lista vacía) — no hay una firma individual a la que aislar el fallo, porque ocurrió antes de poder extraer ninguna.
- Enriquecimiento por firma (validación de cadena + revocación): guardados juntos; un fallo dentro de uno u otro deja esa firma con sus campos de integridad/cobertura/sello ya calculados intactos y su cadena/revocación en sus valores `NOT_CHECKED`/`notChecked()` por defecto, añadiendo una nota a `SignatureReport#anomaly()` (fusionada con cualquier anomalía que el propio `SignatureVerifier` ya hubiera informado, por ejemplo un certificado que no se pudo mapear) — el resto de firmas y el resto del informe no se ven afectados.

`HashCalculator#hash` es la única sección deliberadamente **sin** esta guarda: calcular un hash de un array de bytes no puede fallar de forma significativa con ninguna de las implementaciones de este proyecto, y `PdfAnalysisReport` exige hashes no nulos, así que no hay ningún valor de repuesto razonable que sustituir si de algún modo fallara.

**Tests**: `AnalyzePdfUseCaseTest` (16, con *fakes* escritos a mano para cada puerto, sin Mockito) cubre la orquestación completa, las tres combinaciones de `validationTime`, el flag de revocación activado/desactivado (incluida una firma sin cadena), la declaración PDF/A-2 → `NOT_VALIDATED`, el aislamiento de fallos por sección (PDF/A, firmas, enriquecimiento de una firma sin afectar a las demás, fusión de anomalías), la propagación de `EncryptedPdfException`/`InvalidPdfException`, y `analyzedAt` viniendo del `Clock` inyectado. `AnalyzePdfUseCaseIntegrationTest` (1) cablea los adaptadores reales (sin *fakes*) contra un PDF firmado y sellado en tiempo real (`TestPdfSigner#signWithTimestamp`) con un almacén de confianza que contiene la raíz de prueba usada para firmar, comprobando un informe completo y coherente: integridad íntegra, cadena de confianza `TRUSTED`, sello de tiempo válido.

### 2.10 Arquitectura hexagonal comprobada con ArchUnit (T08)

`src/test/java/.../architecture/ArchitectureTest` sustituye los `grep` manuales que hasta ahora demostraban (tarea a tarea, en la evidencia de este mismo documento) que el dominio no depende de ninguna librería, por una comprobación automática que se ejecuta en cada `./mvnw verify`:

- **`domain` no depende de nada salvo Java puro**: ni Spring, ni PDFBox, ni Bouncy Castle — y, explícitamente, tampoco `java.security.cert` ni `java.awt`, aunque técnicamente formen parte de `java..`: el dominio modela certificados y color con sus propios tipos sin librerías (`CertificateInfo`, cajas numéricas simples) precisamente para no necesitar ninguno de los dos.
- **`application` depende solo de `domain` y Java puro**: el caso de uso orquesta los puertos, nunca un adaptador de infraestructura concreto directamente.
- **`infrastructure` nunca depende de `application` ni de `api`**: los adaptadores implementan puertos del dominio; no deben conocer quién los usa.
- **`api` (aún no existe, T09) solo podrá depender de `application` y `domain`**: la regla usa `allowEmptyShould(true)` para pasar hoy sin ese paquete y empezar a exigirse en cuanto exista.
- **Sin ciclos de importación entre los cuatro paquetes de primer nivel** (`domain`, `application`, `infrastructure`, `api`).

La importación de clases excluye explícitamente los propios tests (`ImportOption.Predefined.DO_NOT_INCLUDE_TESTS`): los *fixtures* de prueba (`TestPdfFactory`, `TestPki`, etc.) usan PDFBox/Bouncy Castle directamente a propósito y no deben hacer fallar estas reglas, que protegen la arquitectura de producción, no las herramientas de test.

## 3. Stack tecnológico

| Área | Tecnología | Versión |
|---|---|---|
| Lenguaje | Java (LTS) | 25 |
| Framework | Spring Boot (Web MVC, Validation, Actuator) | 4.1.1 |
| Motor PDF | Apache PDFBox | 3.0.8 |
| Validación PDF/A | Apache PDFBox *preflight* (PDF/A-1b) | 3.0.8 |
| Criptografía | Bouncy Castle `bcprov` / `bcpkix` (jdk18on) | 1.86 |
| Documentación API | springdoc-openapi (Swagger UI) | 3.1.1 |
| Tests | JUnit 5, AssertJ, Mockito, ArchUnit | — / 1.5.1 |
| Cobertura | JaCoCo | — |
| Build | Maven (wrapper incluido) | 3.9.9 |
| CI | GitHub Actions (Temurin 25) | — |
| Contenedor | Docker, `eclipse-temurin:25-jre-alpine` | ⏳ |
| Frontend | HTML + CSS + JavaScript nativo (sin frameworks) | ⏳ |

## 4. Instalación y ejecución

### Requisitos

- **JDK 25** (en desarrollo se usa OpenLogic OpenJDK 25; en CI y en el contenedor, Eclipse Temurin 25).
- No hace falta instalar Maven: el proyecto incluye el wrapper (`mvnw` / `mvnw.cmd`).

> Si en tu máquina el `java` por defecto es otra versión, define `JAVA_HOME` apuntando al JDK 25 antes de usar el wrapper.

### Compilar y ejecutar los tests

```bash
# Linux / macOS / Git Bash
./mvnw verify

# Windows (cmd / PowerShell)
mvnw.cmd verify
```

`verify` compila, ejecuta todos los tests y genera el informe de cobertura en `target/site/jacoco/index.html`.

### Arrancar la aplicación

```bash
./mvnw spring-boot:run
```

- API REST y Swagger UI (`/swagger-ui.html`): ⏳
- Interfaz web (`/index.html`): ⏳
- Docker / Docker Compose: ⏳

## 5. Estructura del proyecto

Arquitectura **hexagonal** (puertos y adaptadores): el dominio no depende de Spring, PDFBox ni Bouncy Castle; las librerías se usan solo en los adaptadores de infraestructura. Las reglas de dependencia se comprobarán con ArchUnit (⏳).

```
src/main/java/com/coam/pdfvalidator/
├─ PdfValidatorApplication.java   Punto de entrada Spring Boot
├─ domain/                        Java puro, sin librerías externas
│  ├─ model/                      Records inmutables del informe (páginas, firmas, certificados…)
│  ├─ port/                       Interfaces que implementa la infraestructura
│  └─ exception/                  InvalidPdfException, EncryptedPdfException
├─ application/                   AnalyzePdfUseCase (orquestación), AnalysisOptions, NoOpRevocationChecker  ✅
├─ infrastructure/                Adaptadores PDFBox, Bouncy Castle, OCSP/CRL, preflight
│  ├─ crypto/                     JcaHashCalculator (SHA-256/SHA-512)
│  ├─ pdfbox/                     PdfBoxDocumentReader (estructura, seguridad, declaración PDF/A), RevisionCounter
│  ├─ bouncycastle/               BcSignatureVerifier (/ByteRange + CMS, cadena de certificados, sellos RFC 3161)
│  ├─ pki/                        PkixCertificateChainValidator, TrustAnchorProvider (cadena de confianza X.509)
│  └─ preflight/                  PreflightPdfaValidator (validación formal PDF/A-1b)
└─ api/                           Controlador REST, DTOs, gestión de errores  ⏳

src/main/resources/
├─ application.yml                Configuración (límite de subida 20 MB)
├─ truststore/                    Raíces españolas empaquetadas (PEM) + SOURCES.md (procedencia y huellas)
└─ static/                        Interfaz web                           ⏳

src/test/java/com/coam/pdfvalidator/
├─ fixtures/                      Generación de PDFs de prueba (CA de test, firma, cifrado…)
├─ spike/                         Prueba de concepto inicial de verificación de firma
├─ domain/                        Tests del modelo de dominio
├─ application/                   AnalyzePdfUseCaseTest (fakes) + AnalyzePdfUseCaseIntegrationTest (adaptadores reales)
├─ infrastructure/                Tests de los adaptadores (pdfbox, bouncycastle, crypto, pki, preflight)
└─ architecture/                  ArchitectureTest: reglas ArchUnit de la arquitectura hexagonal

odd/tasks/pdf-validator.md        Plan de tareas y evidencias de progreso
.github/workflows/ci.yml          Integración continua
```

## 6. Funcionalidades principales

| Funcionalidad | Estado |
|---|---|
| Verificación de firma CMS y cobertura `/ByteRange` | ✅ |
| Detección de modificación posterior a la firma (actualización incremental) | ✅ |
| Detección de manipulación de bytes firmados | ✅ |
| Firmas múltiples, evaluadas independientemente | ✅ |
| Subfiltros soportados (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`); resto → `UNSUPPORTED` | ✅ |
| `/ByteRange` hostil o inconsistente con `/Contents` → `INVALID_SIGNATURE`, sin excepción | ✅ |
| Hashes SHA-256 / SHA-512 del documento | ✅ |
| Versión (cabecera y catálogo), páginas, rotación, MediaBox/CropBox, orientación | ✅ |
| Número de revisiones (cadena de xref, tolerante a PDF linealizados) | ✅ |
| Cifrado y permisos efectivos | ✅ |
| Datos del certificado firmante y su cadena (sujeto, emisor, fechas, URLs OCSP/CRL) | ✅ |
| Sello de tiempo RFC 3161 (sello de firma; imprint y firma de la TSA) | ✅ |
| Cadena de confianza contra almacén configurable (trust store) | ✅ |
| Revocación OCSP / CRL (opcional, timeout 2 s) | ⏳ |
| Declaración XMP `pdfaid` (lectura) | ✅ |
| Validación formal PDF/A-1b (*preflight*) | ✅ |
| Orquestación completa del análisis (`AnalyzePdfUseCase`): hashes, estructura, PDF/A combinado, firmas enriquecidas con cadena/revocación, aislamiento de fallos por sección | ✅ |
| Arquitectura hexagonal comprobada automáticamente (ArchUnit) | ✅ |
| API REST + Swagger UI | ⏳ |
| Interfaz web con arrastrar y soltar (pantalla **Validar**) | ⏳ |
| Pantalla **Firmar**: firma PAdES con AutoFirma en el equipo del usuario (la clave privada nunca sale de su equipo) y validación del resultado con un clic | ⏳ |
| Despliegue Docker en VM de bajo consumo | ⏳ |

## 7. Tests y calidad

El proyecto se desarrolla con **TDD** (primero el test en rojo, luego la implementación en verde y después la refactorización).

Los PDFs de prueba **se generan por código** (`fixtures/TestPdfFactory`): una CA de pruebas en memoria firma documentos, y a partir de ellos se crean variantes manipuladas, con actualización incremental, rotadas, cifradas o corruptas. Así los tests son reproducibles y no dependen de ficheros con datos personales. Se añadirán 2-3 PDFs reales firmados para los tests de integración (⏳).

| Suite | Qué comprueba |
|---|---|
| `SignatureSpikeTest` | Firma válida, byte manipulado y actualización incremental posterior (prueba de concepto histórica) |
| `TestPdfFactoryTest` | Que cada PDF de prueba tiene la propiedad que dice tener (verificación CMS con un helper propio de `fixtures`, sin depender de `spike`) |
| `domain/model/*Test` | Reglas del modelo: normalización de rotación (estricta y tolerante), orientación, validación de `/ByteRange` (incluidos valores negativos y desbordamiento aritmético), de hashes y de declaración PDF/A, vigencia y comparación por contenido de certificados, consistencia `pageCount`/`pages`, consistencia `rawRotation`/`rotationValid`/`rotation` en `PageInfo`, copias defensivas |
| `JcaHashCalculatorTest` | SHA-256/SHA-512 contra los vectores de prueba conocidos (entrada vacía y `"abc"`) |
| `PdfBoxDocumentReaderTest` | Versión (cabecera/catálogo, incluida cabecera ausente pero fichero cargable), número de páginas, las seis combinaciones de rotación (incluida una inválida y una heredada del nodo `/Pages`) más rotaciones no enteras y no numéricas, orientación (incluida una página en vertical rotada informada como apaisada), MediaBox/CropBox, cifrado (con y sin contraseña de usuario), documento sin cifrar, entrada corrupta o no-PDF, número de revisiones, declaración PDF/A presente/ausente/con XMP corrupto |
| `RevisionCounterTest` | Conteo de revisiones sobre bytes crudos: una sola revisión, dos revisiones encadenadas por `/Prev`, una estructura linealizada construida a mano (una sola revisión lógica), fichero sin cadena de xref reconocible, `/Prev` cíclico (dos secciones que se referencian mutuamente: el recorrido se detiene en vez de bucle infinito), `startxref` fuera de rango (vuelta al conteo por `%%EOF` sin lanzar excepción), un fichero sintético de ~5 MB con 2000 revisiones contado correctamente, y **(T05b)** una comprobación determinista de que el trabajo de escaneo crece linealmente y no cuadráticamente con el tamaño de entrada (contando pasos de escaneo reales mediante un contador expuesto solo para tests, en vez de medir tiempo de reloj — inestable en una CI cargada) |
| `SignatureByteRangeTest` | La comprobación del hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (construida a mano: firma y bytes de PDF fabricados directamente, sin pasar por un fichero real, para poder hacer que ambos discrepen) |
| `BcSignatureVerifierTest` | Documento sin firmar (lista vacía), firma íntegra con su cadena de certificados y URLs OCSP/CRL, actualización incremental posterior a la firma, byte firmado manipulado, doble firma (`MODIFIED_AFTER_SIGNING` + `INTACT`), `/ByteRange` hostil (excede el fichero, longitud negativa) sin lanzar excepción, subfiltro no soportado, sello de tiempo de documento (`ETSI.RFC3161`) como no soportado, entrada corrupta, un campo de firma que lanza una excepción al leerlo (se informa `INVALID_SIGNATURE`, sin abortar el análisis), sello de tiempo de firma ausente/válido/con imprint incorrecto |
| `SignatureTimestampVerifierTest` | Verificador de sellos de tiempo aislado (mismo motivo que `SignatureByteRangeTest`: construir el escenario a mano en vez de por fichero): sin atributo de sello → `absent()`, token con bytes ASN.1 corruptos → inválido con nota, sin lanzar excepción, certificado de la TSA sin el uso extendido de clave `timeStamping` → nota informativa, **(T05b)** un certificado de TSA que no se puede mapear conserva el resto del resultado del sello y añade una nota en vez de descartarlo todo |
| `X509CertificateInfoMapperTest` **(T05b)** | Camino de resiliencia del mapeador de certificados probado directamente (no solo indirectamente vía un PDF real): extensión Authority Information Access o CRL Distribution Points mal formada → sin URLs para esa extensión, sin lanzar excepción |
| `PkixCertificateChainValidatorTest` **(T06, T06b)** | Cadena hasta una raíz de confianza → `TRUSTED`; raíz autofirmada pero ausente del almacén → `UNTRUSTED_ROOT`; falta el certificado intermedio (usando una identidad de tres niveles: raíz → intermedia → firmante) → `INCOMPLETE_CHAIN`; validación posterior a la caducidad del certificado firmante → `EXPIRED`; lista vacía → `NOT_CHECKED`; **(T06b)** un certificado que no se puede parsear desde su DER → `INCOMPLETE_CHAIN`, sin lanzar excepción |
| `TrustAnchorProviderTest` **(T06, T06b, T07b)** | El almacén de confianza empaquetado carga exactamente las raíces documentadas en `truststore/SOURCES.md` (comparando huellas SHA-256, no por red) y todas están vigentes en una fecha de referencia fija (ya no `Instant.now()`); **(T06b)** directorio externo con certificados PEM y DER válidos más un fichero inválido que se omite sin abortar la carga, fichero PKCS#12 real generado en el propio test; **(T07b)** un directorio externo que ni siquiera existe (no se puede listar) se omite igual, sin lanzar excepción |
| `RevisionCounterTest` **(T06b, T07b)** | Además de lo ya cubierto en T03b/T04b: 16 hilos ejecutando `count(...)` concurrentemente sobre distintos documentos obtienen cada uno el conteo correcto (prueba de que no queda estado compartido mutable tras eliminar el contador `static`); **(T07b)** una comprobación adicional específicamente pensada para detectar una regresión (un contador de pasos de escaneo compartido reintroducido): precalcula el conteo de pasos de cada documento en serie y comprueba que muchos hilos concurrentes escaneando documentos de tamaños distintos siguen obteniendo exactamente ese valor cada vez — verificado empíricamente reintroduciendo un contador `static` a propósito y confirmando que este test (y solo este, no el de más arriba) lo detecta |
| `PreflightPdfaValidatorTest` **(T07, T07b)** | Documento sin `OutputIntent` ni XMP → `NON_COMPLIANT` con códigos de error reales de *preflight* (`3.1.3`, `2.4.3`, `7.1`); entrada corrupta (cabecera presente pero estructura rota) → `NOT_VALIDATED`, sin lanzar excepción; entrada cifrada (contraseña de usuario no vacía) → `NOT_VALIDATED` con incidencia `ENCRYPTED`; entrada que no es un PDF en absoluto → `InvalidPdfException`; documento mínimo con `OutputIntent` sRGB (perfil del JDK) y XMP `pdfaid` → `COMPLIANT`, ya sin saltarse en ninguna plataforma; **(T07b)** documento cifrado con contraseña de usuario vacía (rama `probe.isEncrypted()`, distinta de la de excepción) → `NOT_VALIDATED`; más de 200 incidencias sintéticas (con un duplicado exacto) → deduplicadas y truncadas con un marcador `TRUNCATED` |
| `AnalyzePdfUseCaseTest` **(T08)** | Orquestación completa con *fakes* escritos a mano para cada puerto: ensamblado del informe; las tres combinaciones de `validationTime` (sello de tiempo válido, sello inválido con fecha de firma auto-declarada, ninguna de las dos → reloj); revocación desactivada, activada con emisor, activada sin cadena de certificados; declaración PDF/A-2 → `NOT_VALIDATED` (frente a PDF/A-1, que usa el resultado formal tal cual); aislamiento de fallos (validador PDF/A, verificador de firmas, enriquecimiento de una firma sin afectar a otra ni fusionar mal una anomalía ya existente); `analyzedAt` viene del `Clock` inyectado; `EncryptedPdfException`/`InvalidPdfException` se propagan |
| `AnalyzePdfUseCaseIntegrationTest` **(T08)** | El único test de integración de la orquestación: adaptadores reales (sin *fakes*) contra un PDF firmado y sellado en tiempo real (`TestPdfSigner#signWithTimestamp`) con un almacén de confianza que contiene la raíz de prueba usada para firmar — informe completo coherente: integridad `INTACT`, cadena `TRUSTED`, sello de tiempo válido |
| `ArchitectureTest` **(T08)** | Reglas ArchUnit (§2.10): dominio sin librerías (ni siquiera `java.security.cert`/`java.awt`), `application` solo depende de `domain` y Java puro, `infrastructure` nunca depende de `application`/`api`, `api` (aún no existe) solo podrá depender de `application`/`domain`, sin ciclos entre los cuatro paquetes de primer nivel — verificado también introduciendo a propósito una dependencia prohibida y comprobando que la regla correspondiente la detecta |

**Estado actual:** 175 tests, todos en verde (`./mvnw verify`).

PDFs de prueba disponibles en `TestPdfFactory`: sin firmar, multipágina, firmado, firmado y después modificado (actualización incremental), firmado y manipulado, doble firma, firmado con sello de tiempo RFC 3161 válido, firmado con sello de tiempo de imprint incorrecto, páginas rotadas (incluidos valores no normalizados como `-90` o `450`, y una rotación heredada del nodo `/Pages`), apaisado, con CropBox, cifrado con permisos restringidos (AES-256), cifrado con contraseña de usuario vacía, corrupto, no-PDF y con declaración PDF/A (XMP `pdfaid`). La TSA de pruebas (`TestPki.issueTsaIdentity`) es una identidad en memoria independiente de la CA de firma, con un certificado que declara el uso extendido de clave `id-kp-timeStamping`.

## 8. Usuario y contraseña de prueba

**No aplica.** La aplicación no tiene login: es un servicio sin estado que no guarda documentos ni datos de usuario.

## 9. Presentación

Enlace público a las slides: ⏳ *(pendiente)*

## 10. Decisiones técnicas

- **Spring Boot 4.1.1 en lugar de 3.x.** El documento del TFM recomendaba Spring Boot 3.x, pero el soporte OSS de la rama 3.5 (la última 3.x) terminó el 30/06/2026. La 4.1 tiene soporte hasta el 31/07/2027. En Boot 4 el starter web pasa a llamarse `spring-boot-starter-webmvc`.
- **Java 25 en lugar de 21.** Java 25 es la LTS más reciente (soporte hasta 2031) y está dentro del rango soportado por Spring Boot 4.1 (17–26). Aporta mejoras útiles en una VM de poca memoria, como las *compact object headers*. Se descartó Java 27 porque no es LTS y queda fuera del rango soportado por Spring Boot 4.1.
- **OpenLogic en local, Temurin en CI y contenedor.** Las dos distribuciones son OpenJDK con la misma licencia (GPLv2 + Classpath Exception) y la misma política criptográfica (`crypto.policy=unlimited`); no hay diferencias funcionales para el proyecto.
- **PDF/A-1b únicamente.** El módulo *preflight* de PDFBox solo valida PDF/A-1b. Para PDF/A-2/3 se informará de la declaración XMP, pero no se validará formalmente.
- **Revocación opcional y acotada.** Las consultas OCSP/CRL dependen de la red, así que se activan con un parámetro, tienen un timeout de 2 s y, si fallan, el resultado es `UNKNOWN` sin bloquear el resto del análisis.
- **Sin lista de confianza europea (TSL).** La cadena se valida contra un almacén de raíces configurable con las CA españolas.
- **Documento cifrado (contraseña no vacía) o corrupto: se propaga, no se degrada a un informe parcial (T08).** `AnalyzePdfUseCase` deja que `EncryptedPdfException`/`InvalidPdfException` salgan de `analyze(...)` sin capturarlas: no hay un informe parcial razonable para un documento que ni siquiera se pudo abrir. La futura capa REST (T09) debe mapear ambas a `422`.
- **`NoOpRevocationChecker` como implementación provisional (T08, hasta T10).** Cuando se pide comprobar revocación (`checkRevocation=true`) pero el `RevocationChecker` real (OCSP/CRL) todavía no existe, se informa `NOT_CHECKED` con un detalle explícito ("revocation checking not available yet") en vez de fingir que se comprobó — deliberadamente distinto del `notChecked()` que se usa cuando el flag está desactivado.

## 11. Historial de cambios

| Fecha | Cambio |
|---|---|
| 2026-09-26 | Esqueleto Maven + Spring Boot, CI y prueba de concepto de verificación de firma (T01). |
| 2026-09-26 | Paso a Spring Boot 4.1.1 y Java 25 LTS. |
| 2026-09-26 | Generador de PDFs de prueba, modelo de dominio inmutable, puertos y excepciones (T02). |
| 2026-09-27 | Endurecimiento del modelo de dominio frente a `/ByteRange` y rotaciones hostiles (T02b). Calculadora de hashes y lector de estructura/seguridad/PDF/A sobre PDFBox (T03). |
| 2026-09-27 | Conteo de revisiones por cadena de xref (tolerante a PDF linealizados), rotaciones no enteras/no numéricas correctamente marcadas inválidas, cabecera `%PDF-` ausente ya no aborta el análisis (T03b). Verificador de firmas Bouncy Castle: `/ByteRange` + CMS, firmas múltiples independientes, subfiltros soportados/no soportados, extracción de la cadena de certificados con URLs OCSP/CRL (T04). |
| 2026-09-27 | Endurecimiento del verificador de firmas (T04b): comprobación del hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (la anterior era una tautología autorreferencial), conteo de revisiones lineal/acotado en vez de cuadrático (con vuelta a `%%EOF` ante un `startxref` fuera de rango), ningún campo de firma hostil puede ya escapar del guardado por-campo, y un fallo al mapear un certificado ya no degrada una firma criptográficamente válida a `INVALID_SIGNATURE` (se informa con una nota de anomalía). Verificación de sellos de tiempo RFC 3161 sobre el valor de la firma: imprint, firma de la TSA y uso extendido de clave `timeStamping` (T05); los sellos de tiempo de *documento* (`ETSI.RFC3161`) siguen `UNSUPPORTED`, por decisión documentada. |
| 2026-09-27 | Repositorio publicado en GitHub (fusión del commit inicial con la licencia GPL-3.0). CI de GitHub Actions en verde con Temurin 25. |
| 2026-09-27 | (T05b) Un fallo al mapear el certificado de la TSA ya no descarta el resto del resultado del sello de tiempo; camino de resiliencia del mapeador de certificados probado directamente; test de rendimiento del contador de revisiones sustituido por una comprobación determinista (sin reloj de pared). (T06) Validación de cadena de confianza X.509 con la implementación PKIX de la JDK (`PkixCertificateChainValidator`), contra un almacén de confianza configurable (`TrustAnchorProvider`) con seis raíces españolas empaquetadas y verificadas de forma independiente (§2.7). |
| 2026-09-27 | (T06b) `RevisionCounter` ya no guarda su diagnóstico de escaneo en un campo `static` (condición de carrera bajo concurrencia); `PkixCertificateChainValidator` informa un certificado no parseable como `INCOMPLETE_CHAIN` en vez de lanzar excepción; `TrustAnchorProvider` omite (sin abortar) un fichero inválido en el directorio externo, con tests nuevos para directorio externo y PKCS#12; la comprobación de vigencia de las raíces empaquetadas ya usa una fecha de referencia fija en vez de `Instant.now()` (§2.7). (T07) Validación formal PDF/A-1b con el módulo *preflight* de Apache PDFBox (`PreflightPdfaValidator`): `COMPLIANT`/`NON_COMPLIANT` con incidencias deduplicadas y acotadas, `NOT_VALIDATED` para cifrado o fallos internos sin lanzar excepción, `InvalidPdfException` solo para entradas sin cabecera `%PDF-` reconocible; documenta por qué solo se valida formalmente PDF/A-1b (§2.8). |
| 2026-09-27 | (T07b) El fixture PDF/A-1b conforme usa ahora el perfil sRGB del propio JDK en vez del fichero de Windows, así que su test ya no se salta en CI; el sondeo previo de cifrado en `PreflightPdfaValidator` también captura una `RuntimeException` inesperada; nuevos tests para la rama de documento cifrado con contraseña vacía y para la truncación/deduplicación de incidencias a 200; `TrustAnchorProvider` ya no propaga una excepción si el directorio externo no se puede ni listar; el test de concurrencia de `RevisionCounter` se reforzó para detectar específicamente un contador de pasos compartido reintroducido (§2.8). (T08) `AnalyzePdfUseCase`: orquesta todos los puertos del dominio en un único análisis, decide `validationTime` para la cadena de confianza (sello de tiempo válido → fecha de firma auto-declarada → reloj), combina la validación PDF/A-1b formal con la declaración XMP real, resuelve el flag de revocación (con `NoOpRevocationChecker` como implementación provisional hasta T10) y aísla el fallo de una sección para no perder el resto del informe; reglas de arquitectura hexagonal comprobadas automáticamente con ArchUnit (§2.9, §2.10). |

## 12. Repositorio y licencia

- Código fuente: <https://github.com/avalinani/verificador>
- Licencia: [GNU GPL v3.0](LICENSE). Es compatible con las dependencias principales: Apache PDFBox (Apache-2.0) y Bouncy Castle (licencia MIT).
