import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useBusinessContext } from '../context/BusinessContext'
import { storage, db, isFirebaseConfigured } from '../firebase'
import { ref as storageRef, getDownloadURL, deleteObject } from 'firebase/storage'
import { doc, runTransaction } from 'firebase/firestore'
import { EvidenceDoc, BusinessMember } from '../types'

export default function EvidenceLibrary() {
    const { selectedBusiness, currentUserId, canManageSelected } = useBusinessContext()
    const [loadingId, setLoadingId] = useState<string | null>(null)

    const items = selectedBusiness?.evidence ?? []
    const members = selectedBusiness?.members ?? []

    if (!selectedBusiness) {
        return (
            <div className="ids-layout-shell">
                <div className="ids-view-header">
                    <div>
                        <h1>Evidence Library</h1>
                        <p>Select a company to view its Evidence Library.</p>
                    </div>
                </div>
                <section className="ids-surface ids-surface--soft ids-fade-in" style={{ marginBottom: '16px', animationDelay: '0s' }}>
                    <div style={{ padding: '12px' }} />
                </section>
            </div>
        )
    }

    const formatDate = (ts?: string) => {
        if (!ts) return ''
        return ts.split('T')[0]
    }

    const formatTime = (ts?: string) => {
        if (!ts) return ''
        const timePart = ts.split('T')[1]
        return timePart ? timePart.slice(0, 5) : ''
    }

    return (
        <div className="ids-layout-shell">
            <div className="ids-view-header">
                <div>
                    <h1>Evidence Library</h1>
                    <p>Evidence uploaded for the selected company.</p>
                </div>
                <div className="ids-actions-row">
                    <button className="ids-btn">All families</button>
                    <button className="ids-btn">Compliance</button>
                    <button className="ids-btn">Type</button>
                    <button className="ids-btn" onClick={() => { /* reset filters placeholder */ }} style={{ marginLeft: '12px' }}>Reset filters</button>
                </div>
            </div>
            <section className="ids-surface ids-table-card ids-fade-in" style={{ animationDelay: '0.1s' }}>
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Time</th>
                            <th>Title</th>
                            <th>Category</th>
                            <th>Uploaded by</th>
                            <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.length === 0 ? (
                            <tr>
                                <td colSpan={6} className="ids-small" style={{ textAlign: 'center', padding: '18px' }}>
                                    No evidence uploaded yet for this company.
                                </td>
                            </tr>
                        ) : (
                            items.map((item: EvidenceDoc) => {
                                const uploader = members.find((u: BusinessMember) => u.uid === item.uploadedBy)
                                const userName = uploader?.displayName ?? uploader?.email ?? item.uploadedBy ?? 'Unknown'
                                const title = item.id?.split('_', 2)[1] ?? item.id ?? 'Untitled'
                                const category = item.path?.split('/', 2)[1] ?? 'Unknown'

                                return (
                                    <tr key={item.id}>
                                        <td>{formatDate(item.uploadedAt)}</td>
                                        <td>{formatTime(item.uploadedAt)}</td>
                                        <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</td>
                                        <td className="ids-small">{category}</td>
                                        <td className="ids-small">{userName}</td>
                                        <td style={{ textAlign: 'right' }}>
                                            <Link to={`/controls/${category}`} className="ids-btn">›</Link>
                                        </td>
                                    </tr>
                                )
                            })
                        )}
                    </tbody>
                </table>
            </section>
        </div>
    )
}