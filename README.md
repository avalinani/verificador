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
api ──► application: AnalyzePdfUseCase                           ⏳
            │ orquesta los puertos del dominio
            ├─► HashCalculator            SHA-256 / SHA-512       ✅
            ├─► PdfDocumentReader         estructura, páginas, permisos, XMP  ✅
            ├─► SignatureVerifier         /ByteRange + CMS + RFC 3161       ✅
            ├─► CertificateChainValidator PKIX contra trust store            ⏳
            ├─► RevocationChecker         OCSP/CRL (opcional, timeout 2 s)   ⏳
            └─► PdfaConformanceValidator  preflight PDF/A-1b                 ⏳
   ◄── PdfAnalysisReport (JSON)
```

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

**Casos límite, ninguno lanza una excepción**: sin sello → `TimestampInfo.absent()` (`genTime=null`). Sello con imprint incorrecto → `imprintValid=false`, pero la firma que lo contiene sigue `INTACT` si su propio CMS es válido. Sello con bytes ASN.1 corruptos o que no se puede parsear como `TimeStampToken` → se informa igualmente inválido (`genTime=null`, con una nota explicando el motivo), sin afectar a la integridad de la firma.

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
| Cadena y revocación | `ChainStatus`, `RevocationStatus` | Empiezan como `NOT_CHECKED` y se completan más tarde |

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

De cada certificado se leen además las URLs de sus extensiones **Authority Information Access** (OCSP) y **CRL Distribution Points**, si las declara. Una extensión ausente o mal formada no invalida el certificado: simplemente se informa sin URLs para esa extensión. La validación de la cadena contra un almacén de confianza (`chainStatus`) y la comprobación de revocación (`revocation`) quedan, por ahora, como `NOT_CHECKED`/`notChecked()` — las completará el caso de uso en tareas posteriores (T06/T10).

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
├─ application/                   Casos de uso (AnalyzePdfUseCase)       ⏳
├─ infrastructure/                Adaptadores PDFBox, Bouncy Castle, OCSP/CRL, preflight
│  ├─ crypto/                     JcaHashCalculator (SHA-256/SHA-512)
│  ├─ pdfbox/                     PdfBoxDocumentReader (estructura, seguridad, declaración PDF/A), RevisionCounter
│  └─ bouncycastle/               BcSignatureVerifier (/ByteRange + CMS, cadena de certificados)
└─ api/                           Controlador REST, DTOs, gestión de errores  ⏳

src/main/resources/
├─ application.yml                Configuración (límite de subida 20 MB)
└─ static/                        Interfaz web                           ⏳

src/test/java/com/coam/pdfvalidator/
├─ fixtures/                      Generación de PDFs de prueba (CA de test, firma, cifrado…)
├─ spike/                         Prueba de concepto inicial de verificación de firma
├─ domain/                        Tests del modelo de dominio
└─ infrastructure/                Tests de los adaptadores (pdfbox, bouncycastle, crypto)

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
| Cadena de confianza contra almacén configurable (trust store) | ⏳ |
| Revocación OCSP / CRL (opcional, timeout 2 s) | ⏳ |
| Declaración XMP `pdfaid` (lectura) | ✅ |
| Validación formal PDF/A-1b (*preflight*) | ⏳ |
| API REST + Swagger UI | ⏳ |
| Interfaz web con arrastrar y soltar | ⏳ |
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
| `RevisionCounterTest` | Conteo de revisiones sobre bytes crudos: una sola revisión, dos revisiones encadenadas por `/Prev`, una estructura linealizada construida a mano (una sola revisión lógica), fichero sin cadena de xref reconocible, `/Prev` cíclico (dos secciones que se referencian mutuamente: el recorrido se detiene en vez de bucle infinito), `startxref` fuera de rango (vuelta al conteo por `%%EOF` sin lanzar excepción), y un fichero sintético de ~5 MB con 2000 revisiones contado en menos de 3 s (prueba de que el recorrido es lineal, no cuadrático) |
| `SignatureByteRangeTest` | La comprobación del hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (construida a mano: firma y bytes de PDF fabricados directamente, sin pasar por un fichero real, para poder hacer que ambos discrepen) |
| `BcSignatureVerifierTest` | Documento sin firmar (lista vacía), firma íntegra con su cadena de certificados y URLs OCSP/CRL, actualización incremental posterior a la firma, byte firmado manipulado, doble firma (`MODIFIED_AFTER_SIGNING` + `INTACT`), `/ByteRange` hostil (excede el fichero, longitud negativa) sin lanzar excepción, subfiltro no soportado, sello de tiempo de documento (`ETSI.RFC3161`) como no soportado, entrada corrupta, un campo de firma que lanza una excepción al leerlo (se informa `INVALID_SIGNATURE`, sin abortar el análisis), sello de tiempo de firma ausente/válido/con imprint incorrecto |
| `SignatureTimestampVerifierTest` | Verificador de sellos de tiempo aislado (mismo motivo que `SignatureByteRangeTest`: construir el escenario a mano en vez de por fichero): sin atributo de sello → `absent()`, token con bytes ASN.1 corruptos → inválido con nota, sin lanzar excepción, certificado de la TSA sin el uso extendido de clave `timeStamping` → nota informativa |

**Estado actual:** 128 tests, todos en verde (`./mvnw verify`).

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

## 11. Historial de cambios

| Fecha | Cambio |
|---|---|
| 2026-09-26 | Esqueleto Maven + Spring Boot, CI y prueba de concepto de verificación de firma (T01). |
| 2026-09-26 | Paso a Spring Boot 4.1.1 y Java 25 LTS. |
| 2026-09-26 | Generador de PDFs de prueba, modelo de dominio inmutable, puertos y excepciones (T02). |
| 2026-09-27 | Endurecimiento del modelo de dominio frente a `/ByteRange` y rotaciones hostiles (T02b). Calculadora de hashes y lector de estructura/seguridad/PDF/A sobre PDFBox (T03). |
| 2026-09-27 | Conteo de revisiones por cadena de xref (tolerante a PDF linealizados), rotaciones no enteras/no numéricas correctamente marcadas inválidas, cabecera `%PDF-` ausente ya no aborta el análisis (T03b). Verificador de firmas Bouncy Castle: `/ByteRange` + CMS, firmas múltiples independientes, subfiltros soportados/no soportados, extracción de la cadena de certificados con URLs OCSP/CRL (T04). |
| 2026-09-27 | Endurecimiento del verificador de firmas (T04b): comprobación del hueco de `/ByteRange` frente a la longitud de `/Contents` analizada de forma independiente (la anterior era una tautología autorreferencial), conteo de revisiones lineal/acotado en vez de cuadrático (con vuelta a `%%EOF` ante un `startxref` fuera de rango), ningún campo de firma hostil puede ya escapar del guardado por-campo, y un fallo al mapear un certificado ya no degrada una firma criptográficamente válida a `INVALID_SIGNATURE` (se informa con una nota de anomalía). Verificación de sellos de tiempo RFC 3161 sobre el valor de la firma: imprint, firma de la TSA y uso extendido de clave `timeStamping` (T05); los sellos de tiempo de *documento* (`ETSI.RFC3161`) siguen `UNSUPPORTED`, por decisión documentada. |
