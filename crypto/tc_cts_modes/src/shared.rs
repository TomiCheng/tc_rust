use tc_block_cipher::BlockCipher;
use tc_buffered_cipher::BufferedError;

/// 兩種型別共用的狀態，借用各自的儲存：`buffer` 兩個區塊，`chain`、`next`、`block` 各一個
/// 區塊。
pub(crate) struct Buffers<'a> {
    pub(crate) buffer: &'a mut [u8],
    pub(crate) chain: &'a mut [u8],
    pub(crate) next: &'a mut [u8],
    pub(crate) block: &'a mut [u8],
}

/// BC 的 `GetUpdateOutputSize`，但算出確切值：緩衝區總是留下多於一個、至多兩個區塊，其餘
/// 整區塊寫出。區塊大小為 0 時是 0。常數時間：只讀長度。
pub(crate) fn update_output_len<E>(
    buffered: usize,
    block_size: usize,
    input_len: usize,
) -> Result<usize, BufferedError<E>> {
    let total = buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)?;
    if block_size == 0 || total <= block_size {
        return Ok(0);
    }
    Ok((total - block_size - 1) / block_size * block_size)
}

/// BC 的 `GetOutputSize`：已緩衝的加上新的輸入，CTS 的輸出與輸入等長。常數時間：只讀長度。
pub(crate) fn output_len<E>(buffered: usize, input_len: usize) -> Result<usize, BufferedError<E>> {
    buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)
}

/// BC 的 `m_cipherMode.ProcessBlock`：ECB 直接交給 block cipher；CBC 加密時先與 `chain`
/// 互斥或再加密並記下密文，解密時解密後與 `chain` 互斥或，`chain` 換成這個密文。常數時間
/// 程度同 block cipher：只多了互斥或與複製。
fn process_mode<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    chain: &mut [u8],
    next: &mut [u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), C::Error> {
    let n = chain.len();
    if !cbc {
        cipher.process_block(input, output)?;
    } else if encrypting {
        for (chain, input) in chain.iter_mut().zip(input) {
            *chain ^= input;
        }
        cipher.process_block(chain, output)?;
        chain.copy_from_slice(&output[..n]);
    } else {
        next.copy_from_slice(&input[..n]);
        cipher.process_block(input, output)?;
        for (output, chain) in output.iter_mut().zip(chain.iter()) {
            *output ^= chain;
        }
        chain.copy_from_slice(next);
    }
    Ok(())
}

/// BC 的 `ProcessBytes`：緩衝區滿兩個區塊又有更多輸入時，寫出前一個區塊，留下最後兩個
/// 區塊以內的資料給 `do_final`。常數時間程度同 block cipher：只依長度分支與複製。
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_bytes<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    buffers: Buffers<'_>,
    buffered: &mut usize,
    mut input: &[u8],
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    let Buffers {
        buffer,
        chain,
        next,
        ..
    } = buffers;
    let n = chain.len();
    let required = update_output_len(*buffered, n, input.len())?;
    if output.len() < required {
        return Err(BufferedError::OutputTooShort {
            required,
            available: output.len(),
        });
    }
    let mut written = 0;
    let available = buffer.len() - *buffered;
    if input.len() > available {
        buffer[*buffered..].copy_from_slice(&input[..available]);
        input = &input[available..];
        process_mode(
            cipher,
            cbc,
            encrypting,
            chain,
            next,
            &buffer[..n],
            &mut output[..n],
        )
        .map_err(BufferedError::Cipher)?;
        buffer.copy_within(n.., 0);
        *buffered = n;
        written = n;
        while input.len() > n {
            process_mode(
                cipher,
                cbc,
                encrypting,
                chain,
                next,
                &buffer[..n],
                &mut output[written..written + n],
            )
            .map_err(BufferedError::Cipher)?;
            written += n;
            buffer[..n].copy_from_slice(&input[..n]);
            input = &input[n..];
        }
    }
    buffer[*buffered..*buffered + input.len()].copy_from_slice(input);
    *buffered += input.len();
    Ok(written)
}

/// BC 的 `DoFinal`：至少要有一個完整區塊。加密時倒數第二個區塊照模式加密，最後的不完整
/// 區塊以它的尾端補滿、互斥或後直接以 block cipher 加密並放在前面，倒數第二個區塊的密文
/// 截短放在後面；解密反過來。常數時間程度同 block cipher：只依長度分支與複製。
pub(crate) fn do_final<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    buffers: Buffers<'_>,
    buffered: usize,
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    let Buffers {
        buffer,
        chain,
        next,
        block,
    } = buffers;
    let n = chain.len();
    if buffered < n {
        return Err(BufferedError::IncompleteLastBlock);
    }
    if output.len() < buffered {
        return Err(BufferedError::OutputTooShort {
            required: buffered,
            available: output.len(),
        });
    }
    let tail = buffered - n;
    let (first, second) = buffer.split_at_mut(n);
    block.copy_from_slice(first);
    if encrypting {
        process_mode(cipher, cbc, true, chain, next, block, first)
            .map_err(BufferedError::Cipher)?;
        for (index, (second, first)) in second.iter_mut().zip(first.iter()).enumerate() {
            if index < tail {
                *second ^= first;
            } else {
                *second = *first;
            }
        }
        cipher
            .process_block(second, &mut output[..n])
            .map_err(BufferedError::Cipher)?;
        output[n..buffered].copy_from_slice(&first[..tail]);
    } else {
        cipher
            .process_block(block, first)
            .map_err(BufferedError::Cipher)?;
        for (first, second) in first.iter_mut().zip(second.iter_mut()).take(tail) {
            let decrypted = *first;
            *first = *second;
            *second ^= decrypted;
        }
        process_mode(cipher, cbc, false, chain, next, first, &mut output[..n])
            .map_err(BufferedError::Cipher)?;
        output[n..buffered].copy_from_slice(&second[..tail]);
    }
    Ok(buffered)
}
