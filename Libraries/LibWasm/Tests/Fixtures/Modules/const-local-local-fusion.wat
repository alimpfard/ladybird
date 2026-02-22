(module
  ;; i64.const X; local.get 0; local.get 1; i64.add; i64.add
  ;; Expected: X + (param0 + param1)
  (func (export "i64_const_2local_add") (param i64 i64) (result i64)
    i64.const 1000
    local.get 0
    local.get 1
    i64.add
    i64.add
  )

  ;; i64.const X; local.get 0; local.get 1; i64.sub; i64.add
  ;; Expected: X + (param0 - param1)  (sub is non-commutative, tests operand order)
  (func (export "i64_const_2local_sub") (param i64 i64) (result i64)
    i64.const 1000
    local.get 0
    local.get 1
    i64.sub
    i64.add
  )

  ;; i32.const X; local.get 0; local.get 1; i32.add; i32.add
  ;; Expected: X + (param0 + param1)
  (func (export "i32_const_2local_add") (param i32 i32) (result i32)
    i32.const 1000
    local.get 0
    local.get 1
    i32.add
    i32.add
  )

  ;; i32.const X; local.get 0; local.get 1; i32.and; i32.or
  ;; Expected: X | (param0 & param1)
  (func (export "i32_const_2local_and") (param i32 i32) (result i32)
    i32.const 0xFF00
    local.get 0
    local.get 1
    i32.and
    i32.or
  )
)
