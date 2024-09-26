<template>
    <div class="container mb-5">
        <h2 class="fw-bold mb-5">정보광장</h2>
        <hr/>
        <div class="content-wrapper">
            <div class="adjusted-float-popular">
                <FloatPopularContent :showLocationInfo="false" />
            </div>
            <div class="adjusted-main-popular">
                <MainPopularIndustry class=""/>
            </div>
        </div>
    </div>
</template>

<script setup>
import FloatPopularContent from '@/components/infoplaza/FloatPopularContent.vue';
import MainPopularIndustry from '@/components/main/MainPopularIndustry.vue';
</script>

<style>
.content-wrapper {
    display: flex;
    justify-content: space-between;
}

.adjusted-float-popular {
    flex: 2; /* 필요한 크기로 조정 */
}

.adjusted-main-popular {
    flex: 1; /* 필요한 크기로 조정 */
}

/* col-1, col-6에 대한 스타일 재정의 */
.adjusted-float-popular .col-1 {
    flex: 0 0 15%; /* col-1을 20%로 설정 */
    max-width: 15%;
}

.adjusted-float-popular .col-6 {
    flex: 0 0 60%; /* col-6을 50%로 설정 */
    max-width: 60%;
}
</style>
