import { useMemo } from 'react'
import useSWR from 'swr'

export const computeDaysLeft = (notAfter: string): number =>
  Math.floor((new Date(notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24))

export const computeFractionRemaining = (notBefore: string, notAfter: string): number => {
  const expires = new Date(notAfter).getTime()
  const start = new Date(notBefore).getTime()
  const now = new Date().getTime()

  if (expires < now) {
    return 0
  }

  const duration = expires - start

  // defend against potential div-by-zero for weirdly issued certs
  if (duration <= 0) {
    return 0
  }

  return (expires - now) / duration
}

export const useCertificates = () => {
  const { data, error } = useSWR<Certificate.Raw[]>('/certificates')

  const certificates: Certificate.Info[] = useMemo(() => {
    if (!data) return []

    return data.map((cert) => ({
      ...cert,
      daysLeft: computeDaysLeft(cert.notAfter),
      fractionRemaining: computeFractionRemaining(cert.notBefore, cert.notAfter)
    }))
  }, [data])

  return {
    certificates,
    error,
    isLoading: !error && !data,
  }
}

export const useCertificate = (certId: string) => {
  const { data, error } = useSWR<Certificate.Raw>(certId ? `/certificates/${certId}` : null)

  const certificate: Certificate.Info | null = useMemo(() => {
    if (!data) return null

    return {
      ...data,
      daysLeft: computeDaysLeft(data.notAfter),
      fractionRemaining: computeFractionRemaining(data.notBefore, data.notAfter)
    }
  }, [data])

  return {
    certificate,
    error,
    isLoading: !!certId && !error && !data,
  }
}
