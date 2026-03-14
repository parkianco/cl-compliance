;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance.asd - KYC/AML Compliance Framework
;;;; Standalone ASDF system definition

(asdf:defsystem #:cl-compliance
  :description "KYC/AML Compliance Framework for Common Lisp - verification, rule engine, audit"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "0.1.0"
  :serial t
  :depends-on ()
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "conditions")
     (:file "util")
     (:file "crypto")
     (:file "identity")
     (:file "verification")
     (:file "documents")
     (:file "sanctions")
     (:file "monitoring")
     (:file "rules")
     (:file "audit")
     (:file "reporting"))))
  :in-order-to ((asdf:test-op (test-op #:cl-compliance/test))))

(asdf:defsystem #:cl-compliance/test
  :description "Tests for cl-compliance"
  :depends-on (#:cl-compliance)
  :components
  ((:module "test"
    :serial t
    :components
    ((:file "package")
     (:file "identity-test")
     (:file "verification-test")
     (:file "rules-test"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-compliance.test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))
