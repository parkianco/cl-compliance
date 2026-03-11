# cl-compliance

KYC/AML Compliance Framework for Common Lisp with **zero external dependencies**.

## Features

- **Identity verification**: Document and biometric checks
- **Rule engine**: Configurable compliance rules
- **Risk scoring**: Transaction and entity risk assessment
- **Audit logging**: Immutable compliance audit trail
- **Sanctions screening**: OFAC and international watchlists
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-compliance)
```

## Quick Start

```lisp
(use-package :cl-compliance)

;; Create compliance engine
(let ((engine (make-compliance-engine)))
  ;; Check entity
  (check-entity engine
                :entity-id "user-123"
                :documents '(:passport :utility-bill)
                :jurisdiction :us)
  ;; Screen transaction
  (screen-transaction engine
                      :from "user-123"
                      :to "merchant-456"
                      :amount 10000
                      :currency :usd))
```

## API Reference

### Entity Verification

- `(check-entity engine &key entity-id documents jurisdiction)` - Verify entity
- `(get-entity-status engine entity-id)` - Get verification status

### Transaction Screening

- `(screen-transaction engine &key from to amount currency)` - Screen transaction
- `(get-risk-score engine entity-id)` - Get entity risk score

### Audit

- `(get-audit-log engine &key entity-id from-time to-time)` - Query audit log

## Testing

```lisp
(asdf:test-system :cl-compliance)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
