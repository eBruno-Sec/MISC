# Financial Calculator Specifications

## Compound growth

`FV = PV × (1 + r/n)^(n×t)`

## Recurring contribution growth

`FV = PMT × (((1 + i)^N - 1) / i)`

Adjust for beginning-of-period payments by multiplying by `(1 + i)`.

## Present value

`PV = FV / (1 + r)^t`

## Real return

`realReturn = ((1 + nominalReturn) / (1 + inflation)) - 1`

## Future value in today's dollars

`realFV = nominalFV / (1 + inflation)^t`

## Effective annual rate

`EAR = (1 + APR/n)^n - 1`

## Debt payoff

Calculate interest per compounding period, apply payment, and reject scenarios where payment does not exceed accrued interest.

## Requirements

- Define whether rates are nominal or effective.
- Define payment timing.
- Show all assumptions.
- Round for display only, not intermediate calculations.
- Use decimal-safe arithmetic for money.
- Include zero-rate branches.
- Detect invalid or nonconverging scenarios.
- Label results as estimates.
