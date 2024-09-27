
<template lang="">
<div class="container mb-10">
    <div style="display: flex; align-items: flex-end " class="mb-5">
        <h2 style="font-weight: bold">가계관리</h2>
        <p style="margin-left: 20px">
        회원님의 자산 현황을 확인해 보세요.
        </p>
    </div>
    <div class="row">
    <div class="col-5">
        <!-- 왼쪽 카드의 부모 -->
        <div class="card image-card d-flex flex-column">
        <!-- 카드가 세로로 늘어날 수 있도록 설정 -->
            <div class="d-flex justify-content-between align-items-center">
            <img
                src="https://www.jumpoline.com/_file/jumpo/jumpoline_202406121654211156.jpg"
                class="card-img-top rounded"
            />
            </div>
        </div>
    </div>

    <div class="col-3">
        <!-- 오른쪽 카드의 부모 -->
        <div class="card w-100 d-flex flex-column">
        <!-- 카드가 세로로 늘어날 수 있도록 설정 -->
        <div class="card-body pb-5 flex-grow-1">
            <div class="">
            <div class="d-flex justify-content-between gap-4">
                <div class="">
                <span class="d-block text-md text-heading fw-bold"
                    >권리금</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >총 투자액</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >월매출</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >마진율</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >매출이익</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >경비 합계</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >월수익</span
                >
                <span class="d-block text-md text-heading fw-bold"
                    >권리금 회수기간</span
                >
                </div>
                <div class="text-end">
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">100원</span>
                <span class="d-block text-md text-heading fw-bold">1일</span>
                </div>
            </div>
            </div>
        </div>
        </div>
    </div>

    <div class="col-4">
        <StoreGraph/>
    </div>
</div>
</div>
</template>

<script setup>
import StoreGraph from '@/components/main/StoreGraph.vue';

</script>

<style scoped>
</style>
