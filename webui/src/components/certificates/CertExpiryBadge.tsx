import { Badge } from '@traefik-labs/faency'

const expiringSoonCutoff = 0.33

type ExpiryStatus = {
  variant: 'red' | 'orange' | 'green'
  label: string
}

export const getCertExpiryStatus = (fractionRemaining: number): ExpiryStatus => {
  if (fractionRemaining <= 0) return { variant: 'red', label: 'EXPIRED' }
  if (fractionRemaining < expiringSoonCutoff) return { variant: 'orange', label: 'Expiring Soon' }
  return { variant: 'green', label: 'Valid' }
}

type CertExpiryBadgeProps = {
  daysLeft: number
  fractionRemaining: number
  size?: 'small' | 'large'
}

const CertExpiryBadge = ({ daysLeft, fractionRemaining, size = 'large' }: CertExpiryBadgeProps) => {
  const { variant } = getCertExpiryStatus(fractionRemaining)

  return (
    <Badge size={size} variant={variant}>
      {daysLeft < 0 ? 'EXPIRED' : `${daysLeft} days`}
    </Badge>
  )
}

export default CertExpiryBadge
