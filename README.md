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
            ├─► SignatureVerifier         /ByteRange + CMS + RFC 3161        ⏳
            ├─► CertificateChainValidator PKIX contra trust store            ⏳
            ├─► RevocationChecker         OCSP/CRL (opcional, timeout 2 s)   ⏳
            └─► PdfaConformanceValidator  preflight PDF/A-1b                 ⏳
   ◄── PdfAnalysisReport (JSON)
```

### 2.2 Cómo se detecta que un documento ha cambiado después de firmarse

Una firma PDF no firma el fichero entero, sino los bytes indicados en el array **`/ByteRange`** del diccionario de firma. Ese array tiene cuatro números `[a b c d]`: dos tramos de bytes firmados que dejan un hueco en medio donde va la propia firma (`/Contents`, un contenedor CMS en hexadecimal).

La verificación comprueba, en este orden:

1. **Estructura del `/ByteRange`**: el primer tramo empieza en el byte 0 y el hueco entre tramos coincide exactamente con el tamaño de `/Contents`. Si no, la firma es sospechosa.
2. **Integridad matemática**: se calcula el resumen (*digest*) de los bytes cubiertos y se compara con el `messageDigest` firmado dentro del CMS; después se verifica la firma con la clave pública del certificado. Si un solo byte firmado cambia, la verificación falla (**firma inválida**).
3. **Cobertura del fichero**: si el final del segundo tramo (`c + d`) es menor que el tamaño del fichero, hay bytes añadidos **después** de firmar. Es lo que ocurre con las *actualizaciones incrementales* de PDF: la firma sigue siendo válida para su revisión, pero el documento **ha sido modificado después de la firma**.

Estos tres casos (firma válida, byte manipulado y actualización incremental posterior) ya están demostrados con tests (ver [§7](#7-tests-y-calidad)).

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
| Cadena y revocación | `ChainStatus`, `RevocationStatus` | Empiezan como `NOT_CHECKED` y se completan más tarde |

Los **puertos** son interfaces pequeñas que la infraestructura implementará con las librerías: `HashCalculator`, `PdfDocumentReader`, `SignatureVerifier`, `CertificateChainValidator`, `RevocationChecker` y `PdfaConformanceValidator`.

El verificador de firmas devuelve cada `SignatureReport` con la cadena y la revocación sin comprobar. Después, el caso de uso las completa con `withChainAndRevocation(...)`. Así cada adaptador tiene una sola responsabilidad y la revocación puede omitirse sin tocar el verificador.

> **Detalle técnico**: PDFBox reserva un hueco fijo para `/Contents` y lo rellena con ceros. Al extraer la firma hay que leer un único objeto ASN.1 (`ASN1InputStream.readObject()`), porque el constructor directo de `CMSSignedData` de Bouncy Castle rechaza los bytes de relleno ("Extra data detected in stream").

### 2.4 Lectura de estructura, seguridad y declaración PDF/A

`infrastructure/pdfbox/PdfBoxDocumentReader` implementa el puerto `PdfDocumentReader` sobre PDFBox 3 y `xmpbox`, sin dejar escapar ningún tipo de esas librerías fuera del adaptador:

- **Versión**: la de cabecera se extrae directamente de los primeros bytes (`%PDF-x.y`, expresión regular); la del catálogo, con `PDDocumentCatalog#getVersion()` (puede ser `null` si el documento no la declara).
- **Rotación por página**: se lee el atributo raw `/Rotate` con `PDPageTree#getInheritableAttribute`, que además de heredar el valor desde un nodo `/Pages` superior (cuando la página no lo declara ella misma) devuelve el entero **sin normalizar**. Se prefiere a `PDPage#getRotation()` porque este último ya normaliza y hereda, pero cuando el valor no es múltiplo de 90 lo convierte silenciosamente en `0`, ocultando la anomalía. El valor raw pasa por `Rotation.tryFromDegrees(...)`: si es válido se usa para calcular la orientación; si no, `PageInfo` lo expone igualmente (`rawRotation`, `rotationValid()`) y la orientación se calcula como si fuera `0°`, sin abortar el análisis.
- **MediaBox / CropBox y orientación**: se leen con `PDPage#getMediaBox()`/`getCropBox()` (esta última ya hereda de la MediaBox si no está declarada) y se calcula la orientación después de aplicar la rotación efectiva.
- **Número de revisiones**: se cuentan las apariciones no solapadas del marcador `%%EOF` en los bytes crudos del fichero (con un mínimo de 1). Es una heurística a nivel de bytes -en teoría un stream binario podría contener esa secuencia por casualidad- pero es simple y suficiente en esta fase.
- **Cifrado y permisos**: `PDDocument#isEncrypted()` más `AccessPermission`, mapeado a los ocho valores de `Permission`. Un documento sin contraseña de usuario (o con contraseña de usuario vacía) se abre y se informan sus restricciones reales; uno con contraseña de usuario no vacía no puede abrirse y lanza `EncryptedPdfException`.
- **Declaración PDF/A (XMP)**: se exportan los metadatos XMP del catálogo (`PDMetadata`) y se parsean con `DomXmpParser` (del artefacto `xmpbox`, dependencia transitiva de `preflight`, ya en el classpath), extrayendo `pdfaid:part`/`pdfaid:conformance` del esquema `PDFAIdentificationSchema`. Sin metadatos XMP, o sin ese esquema, o con XMP corrupto, se informa `PdfaDeclaration.NONE` en lugar de fallar todo el análisis. Esto es solo la *declaración*; la validación formal PDF/A-1b con *preflight* llega en una tarea posterior.
- Cualquier fichero que PDFBox no pueda parsear (corrupto o que no sea un PDF) lanza `InvalidPdfException`, envolviendo la `IOException` original.

`infrastructure/crypto/JcaHashCalculator` implementa `HashCalculator` con `java.security.MessageDigest` (SHA-256/SHA-512) y `HexFormat`, sin depender de PDFBox ni Bouncy Castle.

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
│  └─ pdfbox/                     PdfBoxDocumentReader (estructura, seguridad, declaración PDF/A)
└─ api/                           Controlador REST, DTOs, gestión de errores  ⏳

src/main/resources/
├─ application.yml                Configuración (límite de subida 20 MB)
└─ static/                        Interfaz web                           ⏳

src/test/java/com/coam/pdfvalidator/
├─ fixtures/                      Generación de PDFs de prueba (CA de test, firma, cifrado…)
├─ spike/                         Prueba de concepto inicial de verificación de firma
└─ domain/                        Tests del modelo de dominio

odd/tasks/pdf-validator.md        Plan de tareas y evidencias de progreso
.github/workflows/ci.yml          Integración continua
```

## 6. Funcionalidades principales

| Funcionalidad | Estado |
|---|---|
| Verificación de firma CMS y cobertura `/ByteRange` (prueba de concepto) | ✅ spike |
| Detección de modificación posterior a la firma (actualización incremental) | ✅ spike |
| Detección de manipulación de bytes firmados | ✅ spike |
| Hashes SHA-256 / SHA-512 del documento | ✅ |
| Versión (cabecera y catálogo), páginas, rotación, MediaBox/CropBox, orientación | ✅ |
| Cifrado y permisos efectivos | ✅ |
| Firmas múltiples y subfiltros (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`) | ⏳ |
| Sello de tiempo RFC 3161 | ⏳ |
| Datos del certificado y cadena de confianza (trust store configurable) | ⏳ |
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
| `SignatureSpikeTest` | Firma válida, byte manipulado y actualización incremental posterior |
| `TestPdfFactoryTest` | Que cada PDF de prueba tiene la propiedad que dice tener (verificación CMS con un helper propio de `fixtures`, sin depender de `spike`) |
| `domain/model/*Test` | Reglas del modelo: normalización de rotación (estricta y tolerante), orientación, validación de `/ByteRange` (incluidos valores negativos y desbordamiento aritmético), de hashes y de declaración PDF/A, vigencia y comparación por contenido de certificados, consistencia `pageCount`/`pages`, copias defensivas |
| `JcaHashCalculatorTest` | SHA-256/SHA-512 contra los vectores de prueba conocidos (entrada vacía y `"abc"`) |
| `PdfBoxDocumentReaderTest` | Versión (cabecera/catálogo), número de páginas, las seis combinaciones de rotación (incluida una inválida y una heredada del nodo `/Pages`), orientación (incluida una página en vertical rotada informada como apaisada), MediaBox/CropBox, cifrado (con y sin contraseña de usuario), documento sin cifrar, entrada corrupta o no-PDF, número de revisiones, declaración PDF/A presente/ausente |

**Estado actual:** 91 tests, todos en verde (`./mvnw verify`).

PDFs de prueba disponibles en `TestPdfFactory`: sin firmar, multipágina, firmado, firmado y después modificado (actualización incremental), firmado y manipulado, doble firma, páginas rotadas (incluidos valores no normalizados como `-90` o `450`, y una rotación heredada del nodo `/Pages`), apaisado, con CropBox, cifrado con permisos restringidos (AES-256), cifrado con contraseña de usuario vacía, corrupto, no-PDF y con declaración PDF/A (XMP `pdfaid`).

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
