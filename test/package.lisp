;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Test Package
;;;; Test suite for compliance framework

(in-package #:cl-compliance.test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defparameter *test-results* '()
  "Results from test runs.")

(defparameter *current-suite* nil
  "Currently running test suite.")

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (handler-case
         (progn ,@body
                (push (list :pass ',name) *test-results*)
                t)
       (error (c)
         (push (list :fail ',name c) *test-results*)
         nil))))

(defmacro assert-true (form &optional message)
  "Assert that form evaluates to true."
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  "Assert that expected equals actual."
  `(unless (equal ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

(defmacro assert-error (error-type &body body)
  "Assert that body signals an error of the given type."
  `(handler-case
       (progn ,@body
              (error "Expected ~A to be signaled" ',error-type))
     (,error-type () t)
     (error (c)
       (error "Expected ~A but got ~A" ',error-type (type-of c)))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-all-tests ()
  "Run all test suites."
  (setf *test-results* '())
  (format t "~%Running cl-compliance tests...~%~%")
  (run-test 'test-identity)
  (run-test 'test-verification)
  (run-test 'test-documents)
  (run-test 'test-sanctions)
  (run-test 'test-monitoring)
  (run-test 'test-rules)
  (run-test 'test-audit)
  (run-test 'test-reporting)
  (report-results))

(defun run-test (test-fn)
  "Run a single test function."
  (setf *current-suite* test-fn)
  (format t "Running ~A...~%" test-fn)
  (funcall test-fn)
  (format t "  Done.~%"))

(defun report-results ()
  "Report test results."
  (let ((passed (count :pass *test-results* :key #'first))
        (failed (count :fail *test-results* :key #'first)))
    (format t "~%========================================~%")
    (format t "Results: ~D passed, ~D failed~%" passed failed)
    (when (> failed 0)
      (format t "~%Failures:~%")
      (dolist (result *test-results*)
        (when (eq (first result) :fail)
          (format t "  ~A: ~A~%" (second result) (third result)))))
    (format t "========================================~%")
    (zerop failed)))
