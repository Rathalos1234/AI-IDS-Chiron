import { useState } from 'react'
import { ref as storageRef, uploadBytesResumable, getDownloadURL, deleteObject } from 'firebase/storage'
import { doc, runTransaction, arrayUnion } from 'firebase/firestore'
import { db, storage, isFirebaseConfigured } from '../firebase'
import { getCurrentUserID } from '../context/AuthRoute'
import { useBusinessContext } from '../context/BusinessContext'
import { BusinessMember } from '../types'

export function EvidenceUploader({ businessId, controlId, disabled }: { businessId: string | null; controlId?: string | null; disabled?: boolean }) {
    const [uploading, setUploading] = useState(false)
    const [progress, setProgress] = useState<number | null>(null)
    const [error, setError] = useState<string | null>(null)

    async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
        setError(null)
        const files = e.target.files
        if (!files || files.length === 0) return
        if (!businessId) {
            setError('No company selected')
            return
        }
        if (!isFirebaseConfigured || !db || !storage) {
            setError('Firebase not configured')
            return
        }

        const file = files[0]
        const user_id = getCurrentUserID()
        console.log(user_id)
        if (!user_id) {
            setError('You must be signed in to upload files')
            return
        }
        const timestamp = Date.now()
        // Storage rule expects: /evidence/{controlId}/{uid}/{fileName}
        const effectiveControlId = controlId ?? businessId ?? 'unknown'         // might change controlId to businessId, not sure yet
    const path = `evidence/${effectiveControlId}/${user_id}/${file.name}`
        const ref = storageRef(storage!, path)

        console.log('Uploading to', path)

        try {
            setUploading(true)
            setProgress(0)
            
            const uploadTask = uploadBytesResumable(ref, file)

            await new Promise<void>((resolve, reject) => {
                uploadTask.on('state_changed', (snapshot) => {
                    console.log("uploading...")
                    const pct = Math.round((snapshot.bytesTransferred / snapshot.totalBytes) * 100)

                    switch (snapshot.state) {
                        case 'paused':
                            console.log('Upload is paused')
                            break;
                        case 'running':
                            console.log('Upload is running')
                            break;
                    }
                    setProgress(pct)
                }, (err) => {
                    console.log("error while uploading...")
                    setError(String(err))
                    setUploading(false)
                    reject(err)
                }, async () => {
                    try {
                        const url = await getDownloadURL(uploadTask.snapshot.ref)
                        // store metadata in Firestore under businesses/{businessId}.evidence array
                        const businessRef = doc(db!, 'businesses', businessId)
                        await runTransaction(db!, async (tx) => {
                            const snap = await tx.get(businessRef)
                            if (!snap.exists()) throw new Error('Business not found')
                            const entry = {
                                id: `${timestamp}_${file.name}`,
                                name: file.name,
                                path,
                                url,
                                uploadedBy: user_id,
                                uploadedAt: new Date(timestamp).toISOString(),
                            }
                            tx.update(businessRef, { evidence: arrayUnion(entry) })
                        })
                        setProgress(100)
                        resolve()
                    } catch (err) {
                        console.error('Upload failed', err)
                        setError(String(err))
                        reject(err)
                    } finally {
                        setUploading(false)
                    }
                })
            })
                // clear file input value
                ; (e.target as HTMLInputElement).value = ''
        } catch (err) {
            console.error('Could not upload...', err)
        } finally {
            setUploading(false)
            setProgress(null)
        }
    }

    return (
        <div style={{ display: 'grid', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input type="file" accept=".pdf,.doc,.docx,.png,.jpg" onChange={handleFile} disabled={Boolean(disabled) || uploading} />
                {uploading && progress !== null && (
                    <span style={{ fontSize: 12, color: 'var(--muted)' }}>{progress}%</span>
                )}
            </div>
            {error && <div style={{ color: '#b91c1c', background: '#fee2e2', padding: '0.5rem', borderRadius: 6 }}>{error}</div>}
        </div>
    )
}


// upload evidence for a given controlId section --------------------------

// lists uploaded evidence for a given controlId
// handles the delete and download actions aswell as displaying the list
 export function EvidenceList({ controlId }: { controlId: string }) {
    const { selectedBusiness, currentUserId, canManageSelected } = useBusinessContext()
    const [loading, setLoading] = useState(false)
    const items = (selectedBusiness?.evidence ?? []).filter((e: any) => e.controlId === controlId || e.path?.includes(controlId))
     const members: BusinessMember[] = selectedBusiness?.members || []

    // delete evidence item
    async function handleDelete(evidenceItem: any) {        //may change the uploaded by to user_name instead of user_id
        if (!selectedBusiness) return
        if (!currentUserId) return
        const isUploader = evidenceItem.uploadedBy === currentUserId
        if (!isUploader && !canManageSelected) return

        setLoading(true)
        try {
            // delete storage object first if path exists
            if (evidenceItem.path) {
                try {
                    const objRef = storageRef(storage!, evidenceItem.path)
                    await deleteObject(objRef)
                } catch (err) {
                    console.warn('Failed to delete storage object (may not exist or permissions), continuing to remove metadata', err)
                }
            }
            const businessRef = doc(db!, 'businesses', selectedBusiness.id)
            await runTransaction(db!, async (tx) => {
                const snap = await tx.get(businessRef)
                if (!snap.exists()) throw new Error('Business not found')
                const data = snap.data() as any
                const newEvidence = (data.evidence ?? []).filter((it: any) => it.id !== evidenceItem.id)
                tx.update(businessRef, { evidence: newEvidence })
            })
        } catch (err) {
            console.error('Failed to remove evidence', err)
        } finally {
            setLoading(false)
        }
    }
    // download evidence item
    // if item has a url, open in new tab
    // if item has a path, get download url and open
    async function handleDownload(item: any) {
        try {
            if (item.url) {
                window.open(item.url, '_blank')
                return
            }
            if (!item.path) return
            const ref = storageRef(storage!, item.path)
            const url = await getDownloadURL(ref)
            window.open(url, '_blank')
        } catch (err) {
            console.error('Failed to get download URL', err)
        }
    }

    if (!selectedBusiness || items.length === 0) {
        return <div style={{ color: 'var(--muted)' }}>No evidence uploaded yet.</div>
    }

    return (
        <div style={{ display: 'grid', gap: 8 }}>
                {items.map((item: any) => {
                const uploader = members.find((u: BusinessMember) => u.uid === item.uploadedBy)
                const userName = uploader?.displayName ?? uploader?.email ?? item.uploadedBy ?? 'Unknown'
                return (
                    <div key={item.id} style={{ display: 'flex', gap: 8, alignItems: 'center', border: '1px solid var(--border)', padding: 8, borderRadius: 6 }}>
                        <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 600 }}>{item.name || item.filename}</div>
                            <div style={{ fontSize: 12, color: 'var(--muted)' }}>Uploaded by {item.uploadedBy} • {new Date(item.uploadedAt).toLocaleString()}</div>
                        </div>
                        <div style={{ display: 'flex', gap: 8 }}>
                            <button type="button" onClick={() => handleDownload(item)} style={{ padding: '6px 8px' }}>Download</button>
                            {(item.uploadedBy === currentUserId || canManageSelected) && (
                                <button type="button" onClick={() => handleDelete(item)} disabled={loading} style={{ padding: '6px 8px', background: '#fef2f2', border: '1px solid #fecaca' }}>Remove</button>
                            )}
                        </div>
                    </div>
                    )
                })}
        </div>
    )
}