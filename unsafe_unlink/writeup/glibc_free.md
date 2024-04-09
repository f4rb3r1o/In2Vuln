# Documenting glibc_free - unsafe_unlink, Linux heap exploitation pt. 1

notes about free()

## __int_free

do_check_inuse_chunk() is being call to check whether this chunk is indeed not already freed.
this is first done by calling inuse(p) macro that do the following:
go to the next consecutive chunk's size field and check if the PREV_INUSE flag is on.

(!) malicious note: If we have heap overflow we can trick malloc to think that victim p freed by overriding the next chunk (mchunkptr nextchunk = p + p->size & ~FLAGS) size field and clearing the PREV_INUSE flag as well as the last user data quadword of p.

So the do_check_inuse_chunk check whether the current chunk indeed used and if is surrounded be free consecutive chunks (prev and next).

Since we are not a fastbin candidates, we skip to line 3960. This is the part where malloc takes care of consolidation:

### next chunk is followed (victim + victim->size & ~FLAGS)
            ### check whether the chunk to be freed is the top chunk (alreay consolidated)
            ### check whether the next chunk is beyond the boundaries of the arena
            ### __glibc_unlikely (!prev_inuse(nextchunk) is checking whether the victim is not already freed
            ### check next chunk size validity (not too big, not too small)
            ### free_perturb is called. This function is 0-ing the user data of the chunk to be freed
            ### in line 4006 malloc start consolidating backwards. This is the intersting part for us since we're overriding our own last quadword of userdata and the next chunk size field to trick malloc into thinking that we're already free. thus controling the bk & fd pointers of our own.
            ### malloc is consolidating backwards by:
            ### summing up the current size and the previous chunk's size
            ### setting the current chunk pointer (p) to the previous chunk
            ### calling unlink(av, p, bck, fwd) - because the previous chunk (ie. now the current chunk), is already freed (hence, consolidation), it resides at some bin. 

            ### backward unlink:
                1) bck is set to p->bk and fwd is set to p->fd.
                2) a check whether p->fd->bk != p and p->bck->fd != p is being done
                3) the bk pointer of the next chunk in the list is set to p->bk 
                    (p->fd->bk will no longer point to p)
                4) the fd pointer of the back chunk in the list is set to p->fd 
                    (p->bk->fd will no loner point to p)
                5) I'll ignore the fd/bk_nextsize operations for now.

                To put it all together, by setting the first two quadward of a chunk A, and overriding the last quadword of chunk A and the size field of a succeeding consecutive chunk to trick malloc that chunk A is freed, and freeing chunk B afterwards:
                    1) Malloc will write our controled fwd pointer to chunkA->bk->fd
                    2) Malloc will write our controled bck pointer to chunkA->fd->bk
                Thus we get 8-bytes write premitive, twice.
                
                The binary we're operting on is lacking the check that chunkA->bk->fd == p and chunkA->fd->bk == p, hence, this method will work.


            ### malloc is consolidating forward by:
            a) summing up the current size and the next chunk's size
            b) calling unlink(av, nextchunk, bck, fwd) - because the next chunk is already freed (hence, consolidation), it resides at some bin.

# unsafe_unlink

## first primitive

So, In the ctf binary, we have an heap overflow bug, allowing us to override 8-bytes of heap memory. 
We'll use it to trick malloc into thinking that the chunkA is already freed. 
This is done by overriding a consecutive chunkB's size field PREV_INUSE flag, along with the last quadword of user data of chunkA with the size of chunkA.

## Abusing the unlinking process

after obtaining the first primitive, we'll free chunkB, making malloc backword consolidate it with chunkA and copying chunkA->bk into chunkA->fd->bk and chunkA->fd into chunkA->bk->fd.
We can set chunkA->fd to &__free_hook, and making the unlinking process copy chunkA->bk info &__free_hook as a result.
we'll write a shellcode into the heap and set the shellcode pointer as chunkA->bk. Thus, pointing the __free_hook to the shellcode ptr.
Since chunkA is not really freed (eventhough malloc think so), we can free it. 
Making __free_hook be called and fire our shellcode. 
