;;;; test/rules-test.lisp - Compliance rule engine tests

(in-package #:cl-compliance.test)

(defun test-rules ()
  "Test compliance rule evaluation."
  (let ((condition (make-rule-condition :type :simple
                                        :field "amount"
                                        :operator :gt
                                        :value 10000)))
    (let ((ctx (list :amount 15000)))
      (assert-true (evaluate-condition condition ctx)
                   "Amount > 10000 should match"))
    (let ((ctx (list :amount 5000)))
      (assert-true (not (evaluate-condition condition ctx))
                   "Amount < 10000 should not match")))
  (push (list :pass 'rules-basic) *test-results*)
  t)
