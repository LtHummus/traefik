import {computeFractionRemaining} from '../../hooks/use-certificates';
import {renderWithProviders, screen} from '../../utils/test';

import CertExpiryBadge, {getCertExpiryStatus} from './CertExpiryBadge'

describe('getCertExpiryStatus', () => {
  it('returns green/valid when greater than 33% time remaining', () => {
    expect(getCertExpiryStatus(0.5)).toEqual({ variant: 'green', label: 'Valid' })
  })

  it('returns orange/expires soon when between 0% and 33% time remaining', () => {
    expect(getCertExpiryStatus(0.31)).toEqual({ variant: 'orange', label: 'Expiring Soon' })
  })

  it('right on the 33% boundary is still green', () => {
    expect(getCertExpiryStatus(0.33)).toEqual({ variant: 'green', label: 'Valid' })
  })

  it('no time remaining, means red', () => {
    expect(getCertExpiryStatus(0)).toEqual({ variant: 'red', label: 'EXPIRED' })
  })
})

describe('computeFractionRemaining', () => {
  const makeIsoTime = (daysFromNow: number) => new Date(Date.now() + (daysFromNow * 24 * 60 * 60 * 1000)).toISOString()

  it('correctly determines fractions for long lived certs', () => {
    expect(computeFractionRemaining(makeIsoTime(-30), makeIsoTime(60))).toBeCloseTo(0.67, 1)
  })

  it('correctly determines fractions for short-lived certs', () => {
    expect(computeFractionRemaining(makeIsoTime(-2), makeIsoTime(4))).toBeCloseTo(0.67, 1)
  })

  it('returns 0 for a cert that is expired', () => {
    expect(computeFractionRemaining(makeIsoTime(-120), makeIsoTime(-30))).toBe(0)
  })

  it('does not divide by zero', () => {
    const someTime = makeIsoTime(-5)
    expect(computeFractionRemaining(someTime, someTime)).toBe(0)
  })
})

describe('<CertExpiryBadge />', () => {
  it('shows remaining time properly when not expired and above 33% remaining', () => {
    renderWithProviders(<CertExpiryBadge daysLeft={42} fractionRemaining={0.5} />)
    expect(screen.getByText('42 days')).toBeInTheDocument()
  })

  it('shows expired when it is ... well ... expired', () => {
    renderWithProviders(<CertExpiryBadge daysLeft={-1} fractionRemaining={0} />)
    expect(screen.getByText('EXPIRED')).toBeInTheDocument()
  })
})
