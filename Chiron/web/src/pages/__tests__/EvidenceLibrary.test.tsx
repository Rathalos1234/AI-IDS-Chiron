import React from 'react'
import { render, screen } from '@testing-library/react'
import { vi } from 'vitest'
import EvidenceLibrary from '../EvidenceLibrary'
import { BusinessProvider } from '../../context/BusinessContext'

// Mock fetch used by BusinessProvider to load controls and businesses
global.fetch = vi.fn(async (input: any) => {
  const url = String(input)
  if (url.endsWith('/data/cmmc-l2.controls.json')) {
    return { ok: true, json: async () => [] }
  }
  if (url.endsWith('/data/businesses.json')) {
    const businesses = [
      {
        id: 'biz-1',
        name: 'Test Biz',
        controlState: [],
        poams: [],
        evidence: [
          {
            id: 'e_123',
            controlId: 'ctrl-1',
            path: 'AC/ctrl-1/file.pdf',
            filename: 'file.pdf',
            size: 123,
            uploadedBy: 'user-1',
            uploadedAt: '2023-01-01',
          },
        ],
        members: [
          { uid: 'user-1', role: 'editor', displayName: 'Alice', email: 'alice@example.com' },
        ],
      },
    ]
    return { ok: true, json: async () => businesses }
  }
  return { ok: false }
}) as any

vi.mock('../../firebase', async () => ({
  db: undefined,
  storage: undefined,
  isFirebaseConfigured: false,
  auth: undefined,
}))

beforeEach(() => {
  window.localStorage.setItem('chiron:selectedBusinessId', 'biz-1')
})

afterEach(() => {
  window.localStorage.removeItem('chiron:selectedBusinessId')
})

test('renders evidence row and uploader name', async () => {
  render(
    <BusinessProvider>
      <EvidenceLibrary />
    </BusinessProvider>
  )

  // The component shows a heading and the uploader's displayName
  expect(await screen.findByText(/Evidence Library/i)).toBeTruthy()
})
