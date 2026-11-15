# The cunho demo

What the public demo runs, next to the issuer itself. Nothing here is part of the engine: a deployment of cunho
for real credentials needs none of it.

The demo runs two cunho instances, as the law has two roles: a PID provider, on cunho's default metadata
directory (the PID as SD-JWT VC and mdoc), and an attestation provider that issues a course certificate, on
`metadata/course`. Both issue made-up data about fictional people.

## The course certificate

`metadata/course` is a metadata directory (`CUNHO_METADATA_DIR`) with two configurations of one attestation, the
certificate a course provider, such as a university or a MOOC platform, gives someone who completed a course:

- `app.foaap.course_certificate_sd_jwt`, an SD-JWT VC of type `https://foaap.app/vct/course-certificate/1`. Its
  Type Metadata is `type_metadata/course-certificate-1.json`, which has to be published byte for byte at that URL,
  since every credential carries its digest (`vct#integrity`); docs/DEMO.md says how, and what to change to run
  the demo under another domain.
- `app.foaap.course_certificate_mdoc`, the same as an mdoc of document type `app.foaap.course_certificate.1`, with
  the data elements in a namespace of the same name; cunho adds the issuing authority, a document number and the
  issue date in `org.iso.23220.1`, as clause 6 of ETSI TS 119 472-1 asks of every mdoc attestation.

The claims follow the fields of the European Learning Model that the EU's learning credential uses (the course's
title and description, learning outcomes, grade, language, study time, EQF level), with the ECTS credits, the
course provider, a link to the course and the day it was completed. The holder is named by family and given name
only: a course certificate needs no birth date or national number. `date_of_issuance` is the day cunho issues it.
Every claim has a label in English and in Portuguese.

Neither configuration asks for key attestation: no rulebook asks it of a course certificate, and leaving it out
lets wallets that cannot attest their keys hold one.

For an mdoc, `language_of_classes` is one text value (`"pt, en"`), and `learning_outcomes` an array of texts; in
the SD-JWT VC both are arrays.
