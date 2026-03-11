;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-compliance - Utility Functions
;;;; Shared utilities for compliance operations

(in-package #:cl-compliance)

;;; ============================================================================
;;; UUID Generation
;;; ============================================================================

(defun generate-uuid ()
  "Generate a random UUID (version 4)."
  (format nil "~8,'0X-~4,'0X-4~3,'0X-~4,'0X-~12,'0X"
          (random #xFFFFFFFF)
          (random #xFFFF)
          (random #xFFF)
          (logior #x8000 (random #x3FFF))
          (random #xFFFFFFFFFFFF)))

;;; ============================================================================
;;; Date/Time Utilities
;;; ============================================================================

(defun current-timestamp ()
  "Return current Unix timestamp."
  (- (get-universal-time) 2208988800))

(defun compute-age (date-of-birth)
  "Compute age in years from date of birth (universal time)."
  (let* ((now (get-universal-time))
         (dob (if (integerp date-of-birth)
                  date-of-birth
                  (parse-date-of-birth date-of-birth))))
    (multiple-value-bind (sec min hour day month year)
        (decode-universal-time now)
      (declare (ignore sec min hour))
      (multiple-value-bind (dob-sec dob-min dob-hour dob-day dob-month dob-year)
          (decode-universal-time dob)
        (declare (ignore dob-sec dob-min dob-hour))
        (let ((age (- year dob-year)))
          (when (or (< month dob-month)
                    (and (= month dob-month) (< day dob-day)))
            (decf age))
          age)))))

(defun parse-date-of-birth (date-string)
  "Parse date string (YYYY-MM-DD) to universal time."
  (let* ((year (parse-integer (subseq date-string 0 4)))
         (month (parse-integer (subseq date-string 5 7)))
         (day (parse-integer (subseq date-string 8 10))))
    (encode-universal-time 0 0 0 day month year)))

(defun format-iso-date (universal-time)
  "Format universal time as ISO 8601 date string."
  (multiple-value-bind (sec min hour day month year)
      (decode-universal-time universal-time)
    (declare (ignore sec min hour))
    (format nil "~4,'0D-~2,'0D-~2,'0D" year month day)))

(defun date-in-range-p (date start-date end-date)
  "Check if DATE is between START-DATE and END-DATE (inclusive)."
  (and (>= date start-date)
       (<= date end-date)))

;;; ============================================================================
;;; Country/Region Utilities
;;; ============================================================================

(defparameter *high-risk-countries*
  '("AF" "BY" "CF" "CU" "CD" "ER" "IR" "IQ" "LB" "LY" "ML" "MM" "NI" "KP"
    "RU" "SO" "SS" "SD" "SY" "VE" "YE" "ZW")
  "ISO 3166-1 alpha-2 codes for high-risk jurisdictions.")

(defun is-high-risk-country-p (country-code)
  "Check if country is high-risk jurisdiction."
  (member (string-upcase country-code) *high-risk-countries* :test #'string=))

(defun normalize-country (country-input)
  "Normalize country input to ISO 3166-1 alpha-2 code."
  (let ((input (string-upcase (string-trim '(#\Space #\Tab) country-input))))
    (cond
      ;; Already ISO alpha-2
      ((= (length input) 2) input)
      ;; Common name mappings
      ((string= input "UNITED STATES") "US")
      ((string= input "USA") "US")
      ((string= input "UNITED KINGDOM") "GB")
      ((string= input "UK") "GB")
      ((string= input "GERMANY") "DE")
      ((string= input "FRANCE") "FR")
      ((string= input "JAPAN") "JP")
      ((string= input "CHINA") "CN")
      ((string= input "CANADA") "CA")
      ((string= input "AUSTRALIA") "AU")
      (t input))))

;;; ============================================================================
;;; String Utilities
;;; ============================================================================

(defun normalize-name (name)
  "Normalize a name for comparison."
  (string-downcase
   (remove-if-not (lambda (c) (or (alpha-char-p c) (char= c #\Space)))
                  (string-trim '(#\Space #\Tab) name))))

(defun generate-name-variants (name)
  "Generate common name variants for fuzzy matching."
  (let ((normalized (normalize-name name))
        (variants '()))
    (push normalized variants)
    ;; Remove middle names
    (let ((parts (split-string normalized #\Space)))
      (when (> (length parts) 2)
        (push (format nil "~A ~A" (first parts) (car (last parts))) variants)))
    ;; Add reversed order
    (let ((parts (split-string normalized #\Space)))
      (when (>= (length parts) 2)
        (push (format nil "~{~A~^ ~}" (reverse parts)) variants)))
    (remove-duplicates variants :test #'string=)))

(defun split-string (string delimiter)
  "Split string by delimiter character."
  (loop for start = 0 then (1+ end)
        for end = (position delimiter string :start start)
        collect (subseq string start (or end (length string)))
        while end))

(defun compute-name-similarity (name1 name2)
  "Compute similarity score between two names (0.0 to 1.0)."
  (let* ((n1 (normalize-name name1))
         (n2 (normalize-name name2))
         (len1 (length n1))
         (len2 (length n2)))
    (if (or (zerop len1) (zerop len2))
        0.0
        (let ((max-len (max len1 len2))
              (distance (levenshtein-distance n1 n2)))
          (- 1.0 (/ (float distance) max-len))))))

(defun levenshtein-distance (s1 s2)
  "Calculate Levenshtein (edit) distance between two strings."
  (let* ((len1 (length s1))
         (len2 (length s2))
         (matrix (make-array (list (1+ len1) (1+ len2)) :initial-element 0)))
    ;; Initialize first row and column
    (loop for i from 0 to len1 do (setf (aref matrix i 0) i))
    (loop for j from 0 to len2 do (setf (aref matrix 0 j) j))
    ;; Fill matrix
    (loop for i from 1 to len1 do
      (loop for j from 1 to len2 do
        (let ((cost (if (char= (char s1 (1- i)) (char s2 (1- j))) 0 1)))
          (setf (aref matrix i j)
                (min (1+ (aref matrix (1- i) j))
                     (1+ (aref matrix i (1- j)))
                     (+ (aref matrix (1- i) (1- j)) cost))))))
    (aref matrix len1 len2)))
