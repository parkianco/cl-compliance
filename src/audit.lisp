;;;; cl-compliance - Audit Trail
;;;; Audit logging and event tracking

(in-package #:cl-compliance)

;;; ============================================================================
;;; Severity Levels
;;; ============================================================================

(defconstant +severity-info+ :info)
(defconstant +severity-warning+ :warning)
(defconstant +severity-error+ :error)
(defconstant +severity-critical+ :critical)

;;; ============================================================================
;;; Categories
;;; ============================================================================

(defconstant +category-authentication+ :authentication)
(defconstant +category-transaction+ :transaction)
(defconstant +category-compliance+ :compliance)
(defconstant +category-security+ :security)

;;; ============================================================================
;;; Audit Structures
;;; ============================================================================

(defstruct audit-event
  "An audit event record."
  (id "" :type string)
  (timestamp 0 :type integer)
  (sequence 0 :type integer)
  (category :compliance :type keyword)
  (severity :info :type keyword)
  (source "" :type string)
  (actor "" :type string)
  (action "" :type string)
  (resource "" :type string)
  (outcome :success :type keyword)
  (details nil)
  (metadata (make-hash-table :test 'equal) :type hash-table)
  (hash "" :type string)
  (prev-hash "" :type string))

(defstruct audit-logger
  "Audit logger instance."
  (store (make-array 0 :fill-pointer 0 :adjustable t) :type vector)
  (sequence 0 :type integer)
  (last-hash "" :type string)
  (config (make-hash-table :test 'equal) :type hash-table)
  (running t :type boolean))

;;; ============================================================================
;;; Logger Operations
;;; ============================================================================

(defparameter *default-logger* nil
  "Default audit logger instance.")

(defun ensure-logger ()
  "Ensure default logger exists."
  (unless *default-logger*
    (setf *default-logger* (make-audit-logger)))
  *default-logger*)

(defun log-event (event &optional (logger (ensure-logger)))
  "Log an audit event."
  ;; Set timestamp if not set
  (when (zerop (audit-event-timestamp event))
    (setf (audit-event-timestamp event) (get-universal-time)))
  ;; Set ID if not set
  (when (string= (audit-event-id event) "")
    (setf (audit-event-id event) (generate-uuid)))
  ;; Set sequence number
  (incf (audit-logger-sequence logger))
  (setf (audit-event-sequence event) (audit-logger-sequence logger))
  ;; Set previous hash
  (setf (audit-event-prev-hash event) (audit-logger-last-hash logger))
  ;; Compute event hash
  (setf (audit-event-hash event) (compute-event-hash event))
  ;; Update last hash
  (setf (audit-logger-last-hash logger) (audit-event-hash event))
  ;; Store event
  (vector-push-extend event (audit-logger-store logger))
  event)

(defun compute-event-hash (event)
  "Compute hash of audit event for chain integrity."
  (hash-pii (format nil "~A:~A:~A:~A:~A:~A:~A"
                    (audit-event-sequence event)
                    (audit-event-timestamp event)
                    (audit-event-category event)
                    (audit-event-actor event)
                    (audit-event-action event)
                    (audit-event-resource event)
                    (audit-event-prev-hash event))))

(defun log-compliance-event (action resource &key actor details outcome)
  "Log a compliance-specific event."
  (log-event (make-audit-event
              :category :compliance
              :severity :info
              :actor (or actor "system")
              :action action
              :resource resource
              :outcome (or outcome :success)
              :details details)))

;;; ============================================================================
;;; Event Search
;;; ============================================================================

(defun get-audit-trail (&key (logger (ensure-logger)) start-time end-time
                              category actor limit)
  "Get audit trail with filters."
  (let ((events '())
        (count 0))
    (loop for event across (audit-logger-store logger)
          when (and (or (null start-time)
                        (>= (audit-event-timestamp event) start-time))
                    (or (null end-time)
                        (<= (audit-event-timestamp event) end-time))
                    (or (null category)
                        (eq (audit-event-category event) category))
                    (or (null actor)
                        (string= (audit-event-actor event) actor)))
          do (push event events)
             (incf count)
          until (and limit (>= count limit)))
    (nreverse events)))

(defun search-events (query &key (logger (ensure-logger)) limit)
  "Search events by text query."
  (let ((events '())
        (count 0)
        (query-lower (string-downcase query)))
    (loop for event across (audit-logger-store logger)
          when (or (search query-lower (string-downcase (audit-event-action event)))
                   (search query-lower (string-downcase (audit-event-resource event)))
                   (search query-lower (string-downcase (audit-event-actor event))))
          do (push event events)
             (incf count)
          until (and limit (>= count limit)))
    (nreverse events)))

;;; ============================================================================
;;; Export
;;; ============================================================================

(defun export-audit-trail (&key (logger (ensure-logger)) format start-time end-time)
  "Export audit trail to specified format."
  (let ((events (get-audit-trail :logger logger
                                  :start-time start-time
                                  :end-time end-time)))
    (case format
      (:json (export-events-json events))
      (:csv (export-events-csv events))
      (otherwise events))))

(defun export-events-json (events)
  "Export events to JSON format (simplified)."
  (with-output-to-string (s)
    (write-char #\[ s)
    (loop for event in events
          for first = t then nil
          do (unless first (write-char #\, s))
             (format s "{\"id\":\"~A\",\"timestamp\":~D,\"category\":\"~A\",\"actor\":\"~A\",\"action\":\"~A\",\"resource\":\"~A\",\"outcome\":\"~A\"}"
                     (audit-event-id event)
                     (audit-event-timestamp event)
                     (audit-event-category event)
                     (audit-event-actor event)
                     (audit-event-action event)
                     (audit-event-resource event)
                     (audit-event-outcome event)))
    (write-char #\] s)))

(defun export-events-csv (events)
  "Export events to CSV format."
  (with-output-to-string (s)
    (format s "id,timestamp,category,actor,action,resource,outcome~%")
    (dolist (event events)
      (format s "~A,~D,~A,~A,~A,~A,~A~%"
              (audit-event-id event)
              (audit-event-timestamp event)
              (audit-event-category event)
              (audit-event-actor event)
              (audit-event-action event)
              (audit-event-resource event)
              (audit-event-outcome event)))))

;;; ============================================================================
;;; Chain Verification
;;; ============================================================================

(defun verify-audit-chain (&key (logger (ensure-logger)))
  "Verify integrity of audit chain."
  (let ((store (audit-logger-store logger))
        (prev-hash ""))
    (loop for i from 0 below (length store)
          for event = (aref store i)
          do (unless (string= (audit-event-prev-hash event) prev-hash)
               (return-from verify-audit-chain
                 (values nil i "Previous hash mismatch")))
             (unless (string= (audit-event-hash event)
                              (compute-event-hash event))
               (return-from verify-audit-chain
                 (values nil i "Event hash mismatch")))
             (setf prev-hash (audit-event-hash event)))
    (values t (length store) "Chain verified")))
